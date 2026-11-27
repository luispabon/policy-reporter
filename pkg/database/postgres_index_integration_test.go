package database

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// newPostgresTestSQLDB opens an independent connection to the schema used by an
// existing test store, so tests can hold locks or write while the store prepares.
func newPostgresTestSQLDB(t *testing.T, schema string) *sql.DB {
	t.Helper()

	dsn := os.Getenv(postgresTestDSNEnv)
	if dsn == "" {
		t.Skipf("set %s to a PostgreSQL URL DSN to run the PostgreSQL index tests", postgresTestDSNEnv)
	}

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", postgresTestDSNEnv, err)
	}

	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(u.String())))
	sqldb.SetMaxOpenConns(1)
	sqldb.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = sqldb.Close() })

	return sqldb
}

func newPostgresTestStoreForSchema(t *testing.T, schema string) *Store {
	t.Helper()

	db := bun.NewDB(newPostgresTestSQLDB(t, schema), pgdialect.New())
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewStore(db, postgresTestVersion)
	if err != nil {
		t.Fatal(err)
	}

	return store
}

type postgresIndexInfo struct {
	name    string
	leading string
	valid   bool
	partial bool
	method  string
}

func postgresTableIndexes(t *testing.T, ctx context.Context, db *bun.DB, table string) []postgresIndexInfo {
	t.Helper()

	rows, err := db.QueryContext(ctx, `
SELECT c.relname, COALESCE(a.attname, ''), i.indisvalid, i.indpred IS NOT NULL, am.amname
FROM pg_index i
JOIN pg_class c ON c.oid = i.indexrelid
JOIN pg_class t ON t.oid = i.indrelid
JOIN pg_namespace n ON n.oid = t.relnamespace
JOIN pg_am am ON am.oid = c.relam
LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = i.indkey[0]
WHERE n.nspname = current_schema() AND t.relname = ?
ORDER BY c.relname`, table)
	if err != nil {
		t.Fatalf("list indexes on %s: %v", table, err)
	}
	defer rows.Close()

	var indexes []postgresIndexInfo
	for rows.Next() {
		var info postgresIndexInfo
		if err := rows.Scan(&info.name, &info.leading, &info.valid, &info.partial, &info.method); err != nil {
			t.Fatalf("scan index on %s: %v", table, err)
		}
		indexes = append(indexes, info)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("list indexes on %s: %v", table, err)
	}

	return indexes
}

func requireLeadingPolicyReportIndex(t *testing.T, ctx context.Context, db *bun.DB, table string) string {
	t.Helper()

	var names []string
	for _, info := range postgresTableIndexes(t, ctx, db, table) {
		if info.leading == "policy_report_id" && info.valid && !info.partial && info.method == "btree" {
			names = append(names, info.name)
		}
	}
	if len(names) != 1 {
		t.Fatalf("%s has %d usable btree indexes leading with policy_report_id (%v), want 1", table, len(names), names)
	}

	return names[0]
}

func requirePostgresChildIndexes(t *testing.T, ctx context.Context, db *bun.DB) {
	t.Helper()

	for _, index := range postgresChildIndexes {
		if name := requireLeadingPolicyReportIndex(t, ctx, db, index.table); name != index.name {
			t.Errorf("%s leading index = %q, want %q", index.table, name, index.name)
		}
	}
}

func requirePostgresSuperuser(t *testing.T, ctx context.Context, db *bun.DB) {
	t.Helper()

	var superuser bool
	if err := db.QueryRowContext(ctx, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").Scan(&superuser); err != nil {
		t.Fatalf("read current user: %v", err)
	}
	if !superuser {
		t.Skip("changing pg_index requires a superuser test role")
	}
}

func requireNoCacheTables(t *testing.T, ctx context.Context, db *bun.DB, schema string) {
	t.Helper()

	var count int
	if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
	AND c.relname IN ('policy_report_config', 'policy_report', 'policy_report_resource', 'policy_report_result', 'policy_report_filter')
	AND n.nspname = ?`, schema).Scan(&count); err != nil {
		t.Fatalf("count cache tables: %v", err)
	}
	if count != 0 {
		t.Errorf("%d cache tables exist in schema %q after a failed prepare, want 0", count, schema)
	}
}

func TestPostgresPrepareDatabaseCreatesChildIndexes(t *testing.T) {
	ctx := context.Background()
	store, db, schema := newPostgresTestStore(t)

	requireTestSchema(t, ctx, db, schema)
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database: %v", err)
	}
	requirePostgresChildIndexes(t, ctx, db)

	// A second prepare with the persisted version only ensures the indexes.
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database with matching version: %v", err)
	}
	requirePostgresChildIndexes(t, ctx, db)
}

func TestPostgresPrepareDatabaseAddsChildIndexesToSameVersionSchema(t *testing.T) {
	ctx := context.Background()
	store, db, schema := newPostgresTestStore(t)

	requireTestSchema(t, ctx, db, schema)
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database: %v", err)
	}
	seedPostgresCache(t, ctx, store, db)

	// Simulate a schema prepared before the child indexes existed.
	for _, index := range postgresChildIndexes {
		if _, err := db.ExecContext(ctx, "DROP INDEX "+index.name); err != nil {
			t.Fatalf("drop index %s: %v", index.name, err)
		}
	}

	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database on an existing schema: %v", err)
	}
	requirePostgresChildIndexes(t, ctx, db)

	after := cacheRowCounts(t, ctx, db)
	for _, table := range cacheTables {
		if after[table] != 0 {
			t.Errorf("%s rows after prepare = %d, want 0", table, after[table])
		}
	}
	if version := cacheVersion(t, ctx, db); version != postgresTestVersion {
		t.Errorf("config version after prepare = %q, want %q", version, postgresTestVersion)
	}
}

func TestPostgresPrepareDatabaseRebuildsSchemaWithChildIndexes(t *testing.T) {
	ctx := context.Background()
	store, db, schema := newPostgresTestStore(t)

	requireTestSchema(t, ctx, db, schema)
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database: %v", err)
	}
	seedPostgresCache(t, ctx, store, db)

	if _, err := db.ExecContext(ctx, "CREATE TABLE unrelated_table (id integer PRIMARY KEY); INSERT INTO unrelated_table VALUES (1)"); err != nil {
		t.Fatalf("create unrelated table: %v", err)
	}

	upgraded, err := NewStore(db, postgresTestVersion+"-next")
	if err != nil {
		t.Fatal(err)
	}

	// The old drop order failed on the resource child foreign key here.
	if err := upgraded.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database with a changed version: %v", err)
	}

	requirePostgresChildIndexes(t, ctx, db)
	if version := cacheVersion(t, ctx, db); version != postgresTestVersion+"-next" {
		t.Errorf("config version after rebuild = %q, want %q", version, postgresTestVersion+"-next")
	}

	var unrelated int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM unrelated_table").Scan(&unrelated); err != nil {
		t.Fatalf("count unrelated table: %v", err)
	}
	if unrelated != 1 {
		t.Errorf("unrelated_table rows after rebuild = %d, want 1", unrelated)
	}
}

func TestPostgresPrepareDatabaseReusesSuitableIndexNames(t *testing.T) {
	ctx := context.Background()
	store, db, schema := newPostgresTestStore(t)

	requireTestSchema(t, ctx, db, schema)
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database: %v", err)
	}

	// Suitable indexes under other names must be reused, including trailing
	// columns and expressions.
	if _, err := db.ExecContext(ctx, "DROP INDEX policy_report_result_policy_report_id_idx"); err != nil {
		t.Fatalf("drop result index: %v", err)
	}
	if _, err := db.ExecContext(ctx, "CREATE INDEX custom_result_parent_idx ON policy_report_result (policy_report_id, policy)"); err != nil {
		t.Fatalf("create result index: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP INDEX policy_report_filter_policy_report_id_idx"); err != nil {
		t.Fatalf("drop filter index: %v", err)
	}
	if _, err := db.ExecContext(ctx, "CREATE INDEX custom_filter_parent_idx ON policy_report_filter (policy_report_id, lower(policy))"); err != nil {
		t.Fatalf("create filter index: %v", err)
	}

	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database with suitable alternate indexes: %v", err)
	}

	if name := requireLeadingPolicyReportIndex(t, ctx, db, "policy_report_result"); name != "custom_result_parent_idx" {
		t.Errorf("policy_report_result leading index = %q, want custom_result_parent_idx", name)
	}
	if name := requireLeadingPolicyReportIndex(t, ctx, db, "policy_report_filter"); name != "custom_filter_parent_idx" {
		t.Errorf("policy_report_filter leading index = %q, want custom_filter_parent_idx", name)
	}
	if name := requireLeadingPolicyReportIndex(t, ctx, db, "policy_report_resource"); name != "policy_report_resource_policy_report_id_idx" {
		t.Errorf("policy_report_resource leading index = %q, want policy_report_resource_policy_report_id_idx", name)
	}

	for _, name := range []string{"policy_report_result_policy_report_id_idx", "policy_report_filter_policy_report_id_idx"} {
		var exists bool
		if err := db.QueryRowContext(ctx, "SELECT to_regclass(?) IS NOT NULL", name).Scan(&exists); err != nil {
			t.Fatalf("resolve %s: %v", name, err)
		}
		if exists {
			t.Errorf("expected index %s was created next to a suitable alternate index", name)
		}
	}
}

func TestPostgresPrepareDatabaseRejectsIncompatibleIndexName(t *testing.T) {
	apply := map[string]func(t *testing.T, ctx context.Context, db *bun.DB, index string){
		"partial index": func(t *testing.T, ctx context.Context, db *bun.DB, index string) {
			if _, err := db.ExecContext(ctx, "CREATE INDEX "+index+" ON policy_report_result (policy_report_id) WHERE policy IS NOT NULL"); err != nil {
				t.Fatalf("create partial index: %v", err)
			}
		},
		"wrong leading column": func(t *testing.T, ctx context.Context, db *bun.DB, index string) {
			if _, err := db.ExecContext(ctx, "CREATE INDEX "+index+" ON policy_report_result (policy, policy_report_id)"); err != nil {
				t.Fatalf("create index with wrong leading column: %v", err)
			}
		},
	}

	for name, create := range apply {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store, db, schema := newPostgresTestStore(t)

			requireTestSchema(t, ctx, db, schema)
			if err := store.PrepareDatabase(ctx); err != nil {
				t.Fatalf("prepare database: %v", err)
			}
			before := seedPostgresCache(t, ctx, store, db)

			index := "policy_report_result_policy_report_id_idx"
			if _, err := db.ExecContext(ctx, "DROP INDEX "+index); err != nil {
				t.Fatalf("drop index: %v", err)
			}
			create(t, ctx, db, index)

			var beforeDefinition string
			if err := db.QueryRowContext(ctx, "SELECT pg_get_indexdef(?::regclass)", index).Scan(&beforeDefinition); err != nil {
				t.Fatalf("read index definition: %v", err)
			}

			err := store.PrepareDatabase(ctx)
			if err == nil {
				t.Fatal("expected prepare to fail on an incompatible index name")
			}
			if !strings.Contains(err.Error(), index) || !strings.Contains(err.Error(), "not a usable btree index") {
				t.Fatalf("prepare error = %v, want a clear incompatible index error", err)
			}

			after := cacheRowCounts(t, ctx, db)
			for _, table := range cacheTables {
				if after[table] != before[table] {
					t.Errorf("%s rows after failed prepare = %d, want %d", table, after[table], before[table])
				}
			}
			if version := cacheVersion(t, ctx, db); version != postgresTestVersion {
				t.Errorf("config version after failed prepare = %q, want %q", version, postgresTestVersion)
			}

			var afterDefinition string
			if err := db.QueryRowContext(ctx, "SELECT pg_get_indexdef(?::regclass)", index).Scan(&afterDefinition); err != nil {
				t.Fatalf("read index definition after failure: %v", err)
			}
			if afterDefinition != beforeDefinition {
				t.Errorf("index definition changed after failed prepare:\nbefore: %s\nafter:  %s", beforeDefinition, afterDefinition)
			}
		})
	}
}

func TestPostgresSuitableIndexesIgnoreInvalidIndex(t *testing.T) {
	ctx := context.Background()
	store, db, schema := newPostgresTestStore(t)

	requireTestSchema(t, ctx, db, schema)
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database: %v", err)
	}

	index := "policy_report_result_policy_report_id_idx"
	if _, err := db.ExecContext(ctx, "DROP INDEX "+index); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	if _, err := db.ExecContext(ctx, "CREATE INDEX "+index+" ON policy_report_result (policy_report_id)"); err != nil {
		t.Fatalf("create index: %v", err)
	}
	requirePostgresSuperuser(t, ctx, db)
	if _, err := db.ExecContext(ctx, "UPDATE pg_index SET indisvalid = false WHERE indexrelid = ?::regclass", index); err != nil {
		t.Fatalf("invalidate index: %v", err)
	}

	var suitable []string
	if err := db.RunInTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted}, func(ctx context.Context, tx bun.Tx) error {
		var err error
		suitable, err = postgresSuitableIndexNames(ctx, tx, "policy_report_result")
		return err
	}); err != nil {
		t.Fatalf("inspect indexes: %v", err)
	}
	if len(suitable) != 0 {
		t.Fatalf("suitable indexes with an invalid index = %v, want none", suitable)
	}

	// The prepare transaction truncates before ensuring indexes and PostgreSQL
	// revalidates an invalid index during TRUNCATE, so prepare succeeds and the
	// index becomes usable.
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database with an invalid index: %v", err)
	}
	if name := requireLeadingPolicyReportIndex(t, ctx, db, "policy_report_result"); name != index {
		t.Errorf("policy_report_result leading index = %q, want %q", name, index)
	}
}

func TestPostgresPrepareDatabaseSerializesConcurrentPreparations(t *testing.T) {
	ctx := context.Background()
	store, db, schema := newPostgresTestStore(t)
	second := newPostgresTestStoreForSchema(t, schema)

	requireTestSchema(t, ctx, db, schema)

	lockDB := newPostgresTestSQLDB(t, schema)
	lockConn, err := lockDB.Conn(ctx)
	if err != nil {
		t.Fatalf("open lock connection: %v", err)
	}
	defer lockConn.Close()

	lockTx, err := lockConn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatalf("begin lock transaction: %v", err)
	}
	defer func() { _ = lockTx.Rollback() }()

	var namespaceOID int64
	if err := lockTx.QueryRowContext(ctx, "SELECT oid FROM pg_namespace WHERE nspname = current_schema()").Scan(&namespaceOID); err != nil {
		t.Fatalf("read schema oid: %v", err)
	}
	if _, err := lockTx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", postgresPrepareLockKey(namespaceOID)); err != nil {
		t.Fatalf("take prepare advisory lock: %v", err)
	}

	first := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		first <- store.PrepareDatabase(ctx)
	}()
	<-started

	select {
	case err := <-first:
		t.Fatalf("prepare finished while another session held the prepare lock: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	if err := lockTx.Commit(); err != nil {
		t.Fatalf("commit lock transaction: %v", err)
	}

	select {
	case err := <-first:
		if err != nil {
			t.Fatalf("prepare after releasing the prepare lock: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("prepare did not finish after releasing the prepare lock")
	}

	results := make(chan error, 2)
	for _, s := range []*Store{store, second} {
		go func(s *Store) { results <- s.PrepareDatabase(ctx) }(s)
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("concurrent prepare: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("concurrent prepare timed out")
		}
	}

	requirePostgresChildIndexes(t, ctx, db)
}

func TestPostgresPrepareDatabaseWaitsForInFlightWriter(t *testing.T) {
	ctx := context.Background()
	store, db, schema := newPostgresTestStore(t)

	requireTestSchema(t, ctx, db, schema)
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database: %v", err)
	}

	writerDB := newPostgresTestSQLDB(t, schema)
	writerConn, err := writerDB.Conn(ctx)
	if err != nil {
		t.Fatalf("open writer connection: %v", err)
	}
	defer writerConn.Close()

	writerTx, err := writerConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin writer transaction: %v", err)
	}
	defer func() { _ = writerTx.Rollback() }()

	if _, err := writerTx.ExecContext(ctx, `INSERT INTO policy_report (id, type, name, namespace, source, labels, skip, pass, warn, fail, error, created)
VALUES ('in-flight-report', 'PolicyReport', 'in-flight', 'default', 'test', '{}', 0, 0, 0, 0, 0, 0)`); err != nil {
		t.Fatalf("insert report in writer transaction: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- store.PrepareDatabase(ctx) }()

	waitForPostgresCacheLockWait(t, ctx, newPostgresTestSQLDB(t, schema))

	select {
	case err := <-done:
		t.Fatalf("prepare finished while a writer transaction held the cache tables: %v", err)
	default:
	}

	if err := writerTx.Commit(); err != nil {
		t.Fatalf("commit writer transaction: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("prepare after the writer committed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("prepare did not finish after the writer committed")
	}

	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM policy_report WHERE id = 'in-flight-report'").Scan(&count); err != nil {
		t.Fatalf("count in-flight report: %v", err)
	}
	if count != 0 {
		t.Errorf("in-flight report rows after prepare = %d, want 0", count)
	}
}

func TestPostgresPrepareDatabaseBlocksWriterUntilCommit(t *testing.T) {
	ctx := context.Background()
	store, db, schema := newPostgresTestStore(t)

	requireTestSchema(t, ctx, db, schema)
	if err := store.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare database: %v", err)
	}
	requirePostgresSuperuser(t, ctx, db)

	for _, index := range postgresChildIndexes {
		if _, err := db.ExecContext(ctx, "DROP INDEX "+index.name); err != nil {
			t.Fatalf("drop index %s: %v", index.name, err)
		}
	}

	// Pause the next preparation after it creates the last child index and
	// before it commits, so a writer can deterministically start while the
	// transaction already holds the cache table locks.
	const pauseKey int64 = 424242
	matchIndex := postgresChildIndexes[len(postgresChildIndexes)-1].name
	pauseFunction := `CREATE FUNCTION pause_cache_index() RETURNS event_trigger LANGUAGE plpgsql AS $$
DECLARE cmd record;
BEGIN
	FOR cmd IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
		IF cmd.command_tag = 'CREATE INDEX' AND cmd.schema_name = '` + schema + `' AND cmd.object_identity LIKE '%` + matchIndex + `' THEN
			PERFORM pg_advisory_xact_lock(` + strconv.FormatInt(pauseKey, 10) + `);
		END IF;
	END LOOP;
END $$`
	if _, err := db.ExecContext(ctx, pauseFunction); err != nil {
		t.Fatalf("create pause function: %v", err)
	}
	trigger := schema + "_pause_index"
	if _, err := db.ExecContext(ctx, "CREATE EVENT TRIGGER "+trigger+" ON ddl_command_end EXECUTE FUNCTION pause_cache_index()"); err != nil {
		t.Fatalf("create pause trigger: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.ExecContext(context.Background(), "DROP EVENT TRIGGER IF EXISTS "+trigger+"; DROP FUNCTION IF EXISTS pause_cache_index()"); err != nil {
			t.Errorf("drop pause trigger: %v", err)
		}
	})

	gateDB := newPostgresTestSQLDB(t, schema)
	gateConn, err := gateDB.Conn(ctx)
	if err != nil {
		t.Fatalf("open gate connection: %v", err)
	}
	defer gateConn.Close()
	gateTx, err := gateConn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin gate transaction: %v", err)
	}
	if _, err := gateTx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", pauseKey); err != nil {
		t.Fatalf("hold pause lock: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- store.PrepareDatabase(ctx) }()

	// Release the gate and join the goroutines on every path, including failures,
	// before cleanups drop the trigger or the schema.
	prepareJoined := false
	var writerDone chan error
	writerJoined := false
	defer func() {
		_ = gateTx.Rollback()
		if !prepareJoined {
			select {
			case err := <-done:
				if err != nil && !t.Failed() {
					t.Errorf("prepare failed during cleanup: %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Errorf("prepare did not finish during cleanup")
			}
		}
		if writerDone != nil && !writerJoined {
			select {
			case err := <-writerDone:
				if err != nil && !t.Failed() {
					t.Errorf("writer failed during cleanup: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Errorf("writer did not finish during cleanup")
			}
		}
	}()

	waitForPostgresAdvisoryWait(t, ctx, newPostgresTestSQLDB(t, schema), pauseKey)

	writerDB := newPostgresTestSQLDB(t, schema)
	writerDone = make(chan error, 1)
	go func() {
		_, err := writerDB.ExecContext(ctx, `INSERT INTO policy_report (id, type, name, namespace, source, labels, skip, pass, warn, fail, error, created)
VALUES ('after-prepare-writer', 'PolicyReport', 'after', 'default', 'test', '{}', 0, 0, 0, 0, 0, 0)`)
		writerDone <- err
	}()

	waitForPostgresRelationLockWait(t, ctx, newPostgresTestSQLDB(t, schema), "policy_report", "RowExclusiveLock")
	select {
	case err := <-writerDone:
		writerJoined = true
		t.Fatalf("writer finished before the prepare transaction committed: %v", err)
	default:
	}

	if err := gateTx.Commit(); err != nil {
		t.Fatalf("release pause lock: %v", err)
	}

	select {
	case err := <-done:
		prepareJoined = true
		if err != nil {
			t.Fatalf("prepare after the writer started: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("prepare did not finish")
	}
	select {
	case err := <-writerDone:
		writerJoined = true
		if err != nil {
			t.Fatalf("writer after the prepare committed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("writer did not finish after the prepare committed")
	}

	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM policy_report WHERE id = 'after-prepare-writer'").Scan(&count); err != nil {
		t.Fatalf("count writer report: %v", err)
	}
	if count != 1 {
		t.Errorf("writer report rows after prepare = %d, want 1", count)
	}
}

func waitForPostgresAdvisoryWait(t *testing.T, ctx context.Context, db *sql.DB, key int64) {
	t.Helper()

	classID := int64(uint64(key) >> 32)
	objectID := int64(uint64(key) & 0xffffffff)
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted AND classid = $1::oid AND objid = $2::oid", classID, objectID).Scan(&waiting); err != nil {
			t.Fatalf("read advisory lock wait: %v", err)
		}
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("prepare did not wait on the pause lock within 10s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitForPostgresRelationLockWait(t *testing.T, ctx context.Context, db *sql.DB, relation, mode string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pg_locks WHERE NOT granted AND relation = $1::regclass AND mode = $2", relation, mode).Scan(&waiting); err != nil {
			t.Fatalf("read pg_locks: %v", err)
		}
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no waiting %s on %s within 5s", mode, relation)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPostgresPrepareDatabaseSkipsCommittedRebuild(t *testing.T) {
	ctx := context.Background()
	_, db, schema := newPostgresTestStore(t)

	requireTestSchema(t, ctx, db, schema)
	requirePostgresSuperuser(t, ctx, db)

	old, err := NewStore(db, postgresTestVersion+"-previous")
	if err != nil {
		t.Fatal(err)
	}
	if err := old.PrepareDatabase(ctx); err != nil {
		t.Fatalf("prepare previous version: %v", err)
	}

	trigger := schema + "_ddl_audit"
	if _, err := db.ExecContext(ctx, "CREATE TABLE ddl_audit (identity text)"); err != nil {
		t.Fatalf("create audit table: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.ExecContext(context.Background(), "DROP EVENT TRIGGER IF EXISTS "+trigger+"; DROP FUNCTION IF EXISTS audit_cache_ddl(); DROP TABLE IF EXISTS ddl_audit"); err != nil {
			t.Errorf("drop ddl audit objects: %v", err)
		}
	})
	if _, err := db.ExecContext(ctx, `CREATE FUNCTION audit_cache_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $$
DECLARE cmd record;
BEGIN
	FOR cmd IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
		IF cmd.command_tag = 'CREATE TABLE' AND cmd.schema_name = '`+schema+`' THEN
			INSERT INTO ddl_audit(identity) VALUES (cmd.object_identity);
		END IF;
	END LOOP;
END $$`); err != nil {
		t.Fatalf("create audit function: %v", err)
	}
	if _, err := db.ExecContext(ctx, "CREATE EVENT TRIGGER "+trigger+" ON ddl_command_end EXECUTE FUNCTION audit_cache_ddl()"); err != nil {
		t.Fatalf("create audit trigger: %v", err)
	}
	if _, err := db.ExecContext(ctx, "TRUNCATE ddl_audit"); err != nil {
		t.Fatalf("clear audit table: %v", err)
	}

	// Both preparers start from the previous version and target the same new
	// version. The loser of the advisory lock must see the committed version
	// and skip a second rebuild.
	first := newPostgresTestStoreForSchema(t, schema)
	second := newPostgresTestStoreForSchema(t, schema)
	results := make(chan error, 2)
	for _, s := range []*Store{first, second} {
		go func(s *Store) { results <- s.PrepareDatabase(ctx) }(s)
	}
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Errorf("concurrent prepare: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("concurrent prepare timed out")
		}
	}

	var creates int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ddl_audit").Scan(&creates); err != nil {
		t.Fatalf("count audited creates: %v", err)
	}
	if creates != len(postgresTargetTables) {
		t.Errorf("CREATE TABLE commands during concurrent upgrade = %d, want %d (one rebuild)", creates, len(postgresTargetTables))
	}
	requirePostgresChildIndexes(t, ctx, db)
	if version := cacheVersion(t, ctx, db); version != postgresTestVersion {
		t.Errorf("config version after concurrent upgrade = %q, want %q", version, postgresTestVersion)
	}
}

func TestPostgresIndexOwnershipError(t *testing.T) {
	index := postgresChildIndexes[0]
	err := wrapPostgresIndexError(index, pgdriver.NewError(map[byte]string{'C': "42501", 'M': "permission denied"}))
	if !strings.Contains(err.Error(), "ownership of the table") {
		t.Errorf("ownership error = %v, want an ownership hint", err)
	}

	plain := wrapPostgresIndexError(index, errors.New("boom"))
	if strings.Contains(plain.Error(), "ownership") {
		t.Errorf("plain error = %v, want no ownership hint", plain)
	}
}

func waitForPostgresCacheLockWait(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting int
		if err := db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM pg_locks l
JOIN pg_class c ON c.oid = l.relation
WHERE NOT l.granted
	AND l.mode = 'AccessExclusiveLock'
	AND c.relname IN ('policy_report', 'policy_report_resource', 'policy_report_result', 'policy_report_filter')`).Scan(&waiting); err != nil {
			t.Fatalf("read pg_locks: %v", err)
		}
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("prepare did not wait on the cache table locks within 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPostgresPrepareDatabaseSearchPath(t *testing.T) {
	t.Run("multi-schema search path", func(t *testing.T) {
		ctx := context.Background()
		store, db, schema := newPostgresTestStore(t)

		requireTestSchema(t, ctx, db, schema)
		if _, err := db.ExecContext(ctx, "SET search_path TO "+schema+", public"); err != nil {
			t.Fatalf("set multi-schema search path: %v", err)
		}

		if err := store.PrepareDatabase(ctx); err != nil {
			t.Fatalf("prepare database with a multi-schema search path: %v", err)
		}
		requirePostgresChildIndexes(t, ctx, db)
	})

	t.Run("target table in later schema", func(t *testing.T) {
		ctx := context.Background()
		store, db, schema := newPostgresTestStore(t)

		requireTestSchema(t, ctx, db, schema)
		later := schema + "_shadow"
		if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+later); err != nil {
			t.Fatalf("create later schema: %v", err)
		}
		t.Cleanup(func() {
			if _, err := db.ExecContext(context.Background(), "DROP SCHEMA IF EXISTS "+later+" CASCADE"); err != nil {
				t.Errorf("drop later schema %s: %v", later, err)
			}
		})
		if _, err := db.ExecContext(ctx, "CREATE TABLE "+later+".policy_report_config (id bigint)"); err != nil {
			t.Fatalf("create shadow config table: %v", err)
		}
		if _, err := db.ExecContext(ctx, "SET search_path TO "+schema+", "+later); err != nil {
			t.Fatalf("set shadowing search path: %v", err)
		}

		err := store.PrepareDatabase(ctx)
		if err == nil || !strings.Contains(err.Error(), "outside current schema") {
			t.Fatalf("prepare error = %v, want a target resolution failure", err)
		}
		requireNoCacheTables(t, ctx, db, schema)
	})

	t.Run("temporary schema", func(t *testing.T) {
		ctx := context.Background()
		store, db, schema := newPostgresTestStore(t)

		requireTestSchema(t, ctx, db, schema)
		if _, err := db.ExecContext(ctx, "CREATE TEMP TABLE temp_probe (id integer)"); err != nil {
			t.Fatalf("create temporary table: %v", err)
		}

		err := store.PrepareDatabase(ctx)
		if err == nil || !strings.Contains(err.Error(), "temporary schema") {
			t.Fatalf("prepare error = %v, want a temporary schema failure", err)
		}
		requireNoCacheTables(t, ctx, db, schema)
	})

	t.Run("empty search path", func(t *testing.T) {
		ctx := context.Background()
		store, db, schema := newPostgresTestStore(t)

		requireTestSchema(t, ctx, db, schema)
		if _, err := db.ExecContext(ctx, "SET search_path TO ''"); err != nil {
			t.Fatalf("clear search path: %v", err)
		}

		err := store.PrepareDatabase(ctx)
		if err == nil || !strings.Contains(err.Error(), "search_path resolves to no schema") {
			t.Fatalf("prepare error = %v, want a missing current schema failure", err)
		}
	})
}

func TestPostgresPrepareLockKey(t *testing.T) {
	if first, second := postgresPrepareLockKey(1), postgresPrepareLockKey(2); first == second {
		t.Fatalf("lock keys for distinct schemas are equal: %d", first)
	}
	if postgresPrepareLockKey(7) != postgresPrepareLockKey(7) {
		t.Fatal("lock key is not deterministic")
	}
	for _, oid := range []int64{0, 1, 1 << 31, 1<<32 - 1} {
		if key := postgresPrepareLockKey(oid); key <= 0 {
			t.Errorf("lock key for namespace oid %d is not positive: %d", oid, key)
		}
	}
}
