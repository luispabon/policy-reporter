# PostgreSQL index preparation

Policy Reporter prepares the PostgreSQL cache tables on startup. This page describes what the preparation does, what the database role needs, and what to check when it fails.

## What happens on startup

PostgreSQL preparation runs in one read committed transaction, before the API serves requests, or in the leadership start hook when leader election is enabled. The transaction:

1. Takes a transaction scoped advisory lock (`pg_advisory_xact_lock`) keyed by the cache schema, so instances of this version preparing the same schema run one after the other.
2. Recreates the cache schema when the persisted version differs from the running binary.
3. Clears the cache with `TRUNCATE TABLE ONLY policy_report, ONLY policy_report_resource, ONLY policy_report_result, ONLY policy_report_filter RESTRICT`.
4. Ensures a btree index leading with `policy_report_id` on the three child tables:
   * `policy_report_resource_policy_report_id_idx`
   * `policy_report_result_policy_report_id_idx`
   * `policy_report_filter_policy_report_id_idx`

Any error rolls the whole transaction back. The previous cache contents, schema and persisted version stay as they were, and the instance does not start serving: it exits without leader election, and the startup hook reports the error with leader election.

## Prerequisites

The role in the database DSN needs:

* Ownership of the four cache tables, or membership in the role that owns them. PostgreSQL only lets a table owner create an index on it automatically.
* The `TRUNCATE` privilege on the four cache tables. Ownership implies it, otherwise grant it explicitly.
* The right to take an `ACCESS EXCLUSIVE` lock on them. Preparation waits until running queries on these tables finish.

On a fresh install the same role creates the tables, so it also needs `CREATE` on the target schema.

## Existing indexes

Preparation reuses any suitable index on `policy_report_resource`, `policy_report_result` or `policy_report_filter`: a live, valid, ready, non-partial btree whose first key column is `policy_report_id` with the default operator class and the column collation. Trailing key columns and expressions are allowed, and the index name does not matter. When no suitable index exists, preparation creates the expected name listed above.

When the expected name is already taken by a relation that is not a suitable index, preparation fails with an explicit error instead of skipping the index (`IF NOT EXISTS`) or dropping an operator created relation.

## Locking and availability

* The `TRUNCATE` keeps an exclusive lock on the four cache tables until commit, so readers and writers of the cache wait while the cache is cleared and the indexes are created.
* The advisory lock waits without a configured timeout, so a second instance waits for the first preparation to commit instead of failing.
* Each instance that prepares clears the shared cache. Starting another replica empties the cache for all instances, as before.

## Search path

The cache schema comes from `search_path`, for example `?search_path=policy_reporter` in the DSN or a role or database default. Preparation accepts a multi schema `search_path` when every existing cache table resolves in the current schema. It rejects preparation when:

* `search_path` includes a temporary schema, because PostgreSQL searches it first.
* Any cache table resolves in a later schema: `table "policy_report" resolves to schema "other" outside current schema "policy_reporter"`.
* `search_path` resolves to no schema.

Tables that do not exist yet are not checked, so a genuinely empty schema is fine.

## Errors and remediation

Missing privilege during index creation:

```text
prepare database: create index "policy_report_result_policy_report_id_idx" on policy_report_result: PostgreSQL requires ownership of the table to create the index automatically: ERROR: must be owner of table policy_report_result (SQLSTATE 42501)
```

Fix by transferring ownership (`ALTER TABLE policy_report_result OWNER TO policy_reporter`) or by granting the owning role to the service role (`GRANT policy_reporter_owner TO policy_reporter`), and by granting `TRUNCATE` when the role is not the owner.

Name conflict:

```text
prepare database: index "policy_report_result_policy_report_id_idx" exists but is not a usable btree index leading with policy_report_id
prepare database: relation name "policy_report_result_policy_report_id_idx" is already used by a "r" relation
```

Fix by renaming or dropping the conflicting relation, or by creating a suitable index on `policy_report_id` under any other name, which preparation then reuses. Policy Reporter never drops or renames existing relations.

An inbound foreign key on `policy_report` makes the cleanup fail with `cannot truncate a table referenced in a foreign key constraint`. Remove the referencing table or constraint before starting.

After fixing the database, restart the instance. Preparation is safe to repeat, and a failed attempt leaves no partial state.

## Rollout cautions

* The advisory lock only coordinates instances that take it, meaning this version and later. Finish a rolling upgrade before relying on the indexes: an older binary preparing the same schema drops and recreates the tables without them, so the child tables lose their `policy_report_id` indexes until an instance of this version prepares again.
* Instance starts still clear the shared cache, so a replica restart is not free while other instances use the same database.
* A failing preparation blocks startup. Expect `CrashLoopBackOff` without leader election until the role and conflicting relations are fixed.

## Tests

PostgreSQL preparation tests use `POLICY_REPORTER_TEST_POSTGRES_DSN` and skip when it is unset:

```bash
POLICY_REPORTER_TEST_POSTGRES_DSN='postgres://user:password@localhost:5432/policy_reporter_test?sslmode=disable' \
  go test ./pkg/database -run 'Postgres' -v -timeout 5m
```

Use a disposable database and a direct connection, not a transaction mode pooler. The tests create and drop schemas named `policy_reporter_cleanup_*`, so the role needs `CREATE` on the database. Tests that need to modify `pg_index` require a superuser and skip otherwise.
