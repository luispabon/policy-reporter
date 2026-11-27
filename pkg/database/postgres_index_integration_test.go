package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/kyverno/policy-reporter/pkg/fixtures"
	"github.com/kyverno/policy-reporter/pkg/report/result"
)

// postgresTestDSN returns POLICY_REPORTER_TEST_POSTGRES_DSN, so PostgreSQL tests
// are opt-in. For example:
//
//	POLICY_REPORTER_TEST_POSTGRES_DSN=postgres://postgres:password@127.0.0.1:5432/postgres \
//	  go test ./pkg/database -run Postgres
func postgresTestDSN(t *testing.T) string {
	t.Helper()

	dsn := os.Getenv("POLICY_REPORTER_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set POLICY_REPORTER_TEST_POSTGRES_DSN to run PostgreSQL tests")
	}

	return dsn
}

// createPostgresSchema creates a disposable schema that is dropped afterwards.
func createPostgresSchema(t *testing.T, prefix string) string {
	t.Helper()

	admin := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(postgresTestDSN(t))))
	t.Cleanup(func() { _ = admin.Close() })

	schema := fmt.Sprintf("%s%d_%d", prefix, time.Now().UnixNano(), os.Getpid())
	if _, err := admin.ExecContext(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema %s: %v", schema, err)
	}
	t.Cleanup(func() {
		if _, err := admin.ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema %s: %v", schema, err)
		}
	})

	return schema
}

// newPostgresStore returns a store bound to a fresh disposable schema.
func newPostgresStore(t *testing.T, version string) (*Store, *bun.DB) {
	t.Helper()

	return newPostgresStoreIn(t, version, createPostgresSchema(t, "s"))
}

// newPostgresStoreIn returns a store whose connections use searchPath.
func newPostgresStoreIn(t *testing.T, version, searchPath string) (*Store, *bun.DB) {
	t.Helper()

	dsn := postgresTestDSN(t)
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	db := bun.NewDB(sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn+separator+"search_path="+searchPath))), pgdialect.New())
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})

	store, err := NewStore(db, version)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	return store, db
}

func countQuery(t *testing.T, db *bun.DB, query string, args ...any) int {
	t.Helper()

	var count int
	if err := db.NewRaw(query, args...).Scan(context.Background(), &count); err != nil {
		t.Fatalf("query %q: %v", query, err)
	}

	return count
}

const indexCountQuery = `SELECT COUNT(*) FROM pg_index i
	JOIN pg_class ic ON ic.oid = i.indexrelid
	JOIN pg_class tc ON tc.oid = i.indrelid
	JOIN pg_namespace n ON n.oid = tc.relnamespace
	WHERE n.nspname = current_schema() AND tc.relname = ? AND ic.relname = ? AND i.indisvalid`

const partialIndexCountQuery = `SELECT COUNT(*) FROM pg_index i
	JOIN pg_class ic ON ic.oid = i.indexrelid
	JOIN pg_class tc ON tc.oid = i.indrelid
	JOIN pg_namespace n ON n.oid = tc.relnamespace
	WHERE n.nspname = current_schema() AND ic.relname = ? AND i.indpred IS NOT NULL`

func relationCount(t *testing.T, db *bun.DB, name string) int {
	t.Helper()

	return countQuery(t, db, `SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relname = ?`, name)
}

func requirePolicyReportIndexes(t *testing.T, db *bun.DB) {
	t.Helper()

	for _, table := range policyReportIndexTables {
		name := table + "_policy_report_id_idx"
		if count := countQuery(t, db, indexCountQuery, table, name); count != 1 {
			t.Fatalf("%s has %d usable %s indexes, want 1", table, count, name)
		}
	}
}

func requireVersion(t *testing.T, db *bun.DB, version string) {
	t.Helper()

	if count := countQuery(t, db, "SELECT COUNT(*) FROM policy_report_config WHERE id = 1 AND version = ?", version); count != 1 {
		t.Fatalf("stored version %q rows = %d, want 1", version, count)
	}
}

func TestPrepareDatabasePostgresLifecycle(t *testing.T) {
	ctx := context.Background()
	store, db := newPostgresStore(t, "v1")
	rep := result.NewReconditioner(nil).Prepare(fixtures.DefaultPolicyReport)

	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare fresh database: %v", err)
	}
	requirePolicyReportIndexes(t, db)
	requireVersion(t, db, "v1")

	if err := store.Add(ctx, rep); err != nil {
		t.Fatalf("add report: %v", err)
	}
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare existing database: %v", err)
	}
	if count := countQuery(t, db, "SELECT COUNT(*) FROM policy_report"); count != 0 {
		t.Fatalf("reports after cleanup = %d, want 0", count)
	}
	requirePolicyReportIndexes(t, db)
	requireVersion(t, db, "v1")

	if err := store.Add(ctx, rep); err != nil {
		t.Fatalf("add report: %v", err)
	}
	if count := countQuery(t, db, "SELECT COUNT(*) FROM policy_report_result"); count == 0 {
		t.Fatal("expected child rows before the rebuild")
	}

	upgraded, err := NewStore(db, "v2")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if err := upgraded.PrepareDatabase(ctx); err != nil {
		t.Fatalf("rebuild database: %v", err)
	}
	requirePolicyReportIndexes(t, db)
	requireVersion(t, db, "v2")
	if count := countQuery(t, db, "SELECT COUNT(*) FROM policy_report"); count != 0 {
		t.Fatalf("reports after rebuild = %d, want 0", count)
	}
}

func TestPrepareDatabasePostgresIndexReuseAndCollision(t *testing.T) {
	ctx := context.Background()
	store, db := newPostgresStore(t, "v1")
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare fresh database: %v", err)
	}

	if _, err := db.ExecContext(ctx, "DROP INDEX policy_report_result_policy_report_id_idx"); err != nil {
		t.Fatalf("drop reserved result index: %v", err)
	}
	if _, err := db.ExecContext(ctx, "CREATE INDEX operator_result_idx ON policy_report_result (policy_report_id, source)"); err != nil {
		t.Fatalf("create operator index: %v", err)
	}
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare with operator index: %v", err)
	}
	if count := countQuery(t, db, indexCountQuery, "policy_report_result", "operator_result_idx"); count != 1 {
		t.Fatalf("operator index is not usable")
	}
	if count := relationCount(t, db, "policy_report_result_policy_report_id_idx"); count != 0 {
		t.Fatalf("reserved result index was created although operator_result_idx is usable")
	}

	if _, err := db.ExecContext(ctx, "DROP INDEX policy_report_filter_policy_report_id_idx"); err != nil {
		t.Fatalf("drop reserved filter index: %v", err)
	}
	if _, err := db.ExecContext(ctx, "CREATE INDEX policy_report_filter_policy_report_id_idx ON policy_report_filter (policy_report_id) WHERE source = 'never'"); err != nil {
		t.Fatalf("create partial filter index: %v", err)
	}
	rep := result.NewReconditioner(nil).Prepare(fixtures.DefaultPolicyReport)
	if err := store.Add(ctx, rep); err != nil {
		t.Fatalf("add report: %v", err)
	}
	reports := countQuery(t, db, "SELECT COUNT(*) FROM policy_report")

	err := store.PrepareDatabase(ctx)
	if err == nil || !strings.Contains(err.Error(), "policy_report_filter_policy_report_id_idx") {
		t.Fatalf("prepare with reserved index collision = %v, want the index name", err)
	}
	if count := countQuery(t, db, "SELECT COUNT(*) FROM policy_report"); count != reports {
		t.Fatalf("reports after failed preparation = %d, want %d", count, reports)
	}
	requireVersion(t, db, "v1")
	if count := countQuery(t, db, indexCountQuery, "policy_report_result", "operator_result_idx"); count != 1 {
		t.Fatalf("operator index was lost by the failed preparation")
	}
	if count := countQuery(t, db, partialIndexCountQuery, "policy_report_filter_policy_report_id_idx"); count != 1 {
		t.Fatalf("partial filter index was replaced or dropped")
	}
}

func TestPrepareDatabasePostgresSerializesInitializers(t *testing.T) {
	ctx := context.Background()
	store, db := newPostgresStore(t, "v1")
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare fresh database: %v", err)
	}

	var configOID int64
	if err := db.NewRaw("SELECT 'policy_report_config'::regclass::oid").Scan(ctx, &configOID); err != nil {
		t.Fatalf("read config oid: %v", err)
	}

	lockTx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatalf("begin lock transaction: %v", err)
	}
	defer func() { _ = lockTx.Rollback() }()
	if _, err := lockTx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(?)", prepareLockKey); err != nil {
		t.Fatalf("take prepare lock: %v", err)
	}

	upgraded, err := NewStore(db, "v2")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- upgraded.PrepareDatabase(ctx) }()

	// A cooperating initializer waits for the lock instead of preparing.
	waitForAdvisoryLockWaiter(t, db)

	if _, err := lockTx.ExecContext(ctx, "UPDATE policy_report_config SET version = 'v2'"); err != nil {
		t.Fatalf("persist new version: %v", err)
	}
	if err := lockTx.Commit(); err != nil {
		t.Fatalf("commit new version: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("second initializer: %v", err)
	}

	var currentOID int64
	if err := db.NewRaw("SELECT 'policy_report_config'::regclass::oid").Scan(ctx, &currentOID); err != nil {
		t.Fatalf("read config oid: %v", err)
	}
	if currentOID != configOID {
		t.Fatalf("second initializer rebuilt the schema instead of reading version v2")
	}
	requireVersion(t, db, "v2")
}

func TestPrepareDatabasePostgresFailsClosedOnSearchPath(t *testing.T) {
	ctx := context.Background()

	t.Run("table in later schema", func(t *testing.T) {
		target := createPostgresSchema(t, "d")
		store, db := newPostgresStoreIn(t, "v1", target)
		if err := store.PrepareDatabase(ctx); err != nil {
			t.Fatalf("prepare target schema: %v", err)
		}
		rep := result.NewReconditioner(nil).Prepare(fixtures.DefaultPolicyReport)
		if err := store.Add(ctx, rep); err != nil {
			t.Fatalf("add report: %v", err)
		}
		reports := countQuery(t, db, "SELECT COUNT(*) FROM policy_report")
		if reports == 0 {
			t.Fatal("expected stored reports")
		}

		first := createPostgresSchema(t, "e")
		guarded, guardedDB := newPostgresStoreIn(t, "v2", target)
		guardedDB.SetMaxOpenConns(1)
		if _, err := guardedDB.ExecContext(ctx, "SET search_path TO "+first+", "+target); err != nil {
			t.Fatalf("set search_path: %v", err)
		}
		err := guarded.PrepareDatabase(ctx)
		if err == nil || !strings.Contains(err.Error(), "search_path") {
			t.Fatalf("prepare with tables in a later schema = %v, want a search_path error", err)
		}

		if count := countQuery(t, guardedDB, "SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = ?", first); count != 0 {
			t.Fatalf("%s holds %d relations, want 0", first, count)
		}
		if count := countQuery(t, db, "SELECT COUNT(*) FROM policy_report"); count != reports {
			t.Fatalf("reports after refused preparation = %d, want %d", count, reports)
		}
		requireVersion(t, db, "v1")
	})

	t.Run("temporary schema", func(t *testing.T) {
		store, db := newPostgresStore(t, "v1")
		db.SetMaxOpenConns(1)
		if err := store.PrepareDatabase(ctx); err != nil {
			t.Fatalf("prepare fresh database: %v", err)
		}
		rep := result.NewReconditioner(nil).Prepare(fixtures.DefaultPolicyReport)
		if err := store.Add(ctx, rep); err != nil {
			t.Fatalf("add report: %v", err)
		}
		reports := countQuery(t, db, "SELECT COUNT(*) FROM policy_report")
		if _, err := db.ExecContext(ctx, "CREATE TEMP TABLE shadow (id int)"); err != nil {
			t.Fatalf("create temporary table: %v", err)
		}

		err := store.PrepareDatabase(ctx)
		if err == nil || !strings.Contains(err.Error(), "temporary schema") {
			t.Fatalf("prepare with a temporary schema = %v, want a temporary schema error", err)
		}
		if count := countQuery(t, db, "SELECT COUNT(*) FROM policy_report"); count != reports {
			t.Fatalf("reports after refused preparation = %d, want %d", count, reports)
		}
	})
}

// waitForAdvisoryLockWaiter waits until another session in this database is
// blocked on the preparation lock.
func waitForAdvisoryLockWaiter(t *testing.T, db *bun.DB) {
	t.Helper()

	const query = `SELECT COUNT(*) FROM pg_locks
		WHERE locktype = 'advisory' AND NOT granted AND objsubid = 1
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
			AND classid = ?::oid AND objid = ?::oid`
	class, object := prepareLockKey>>32, prepareLockKey&0xffffffff

	deadline := time.Now().Add(10 * time.Second)
	for {
		if countQuery(t, db, query, class, object) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("second initializer did not wait for the preparation lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
