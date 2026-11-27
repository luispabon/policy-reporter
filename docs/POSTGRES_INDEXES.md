# PostgreSQL indexes

PostgreSQL does not index a foreign key. Without an index on
`policy_report_id`, cleanup and cascade deletes scan `policy_report_filter`,
`policy_report_result` and `policy_report_resource` in full for every removed
report.

`PrepareDatabase` ensures such an index on each child table, before the cleanup
delete, for fresh databases, existing databases and rebuilds. A valid,
non-partial btree index whose first key column is `policy_report_id` with the
column collation is reused; otherwise the reserved name
`<table>_policy_report_id_idx` is created. No index is ever dropped.

## Schema requirements

Preparation owns five table names in the selected schema:
`policy_report_config`, `policy_report`, `policy_report_result`,
`policy_report_filter` and `policy_report_resource`. It drops and recreates
them when the config table or its version row is missing, or when the stored
version differs. Reserve these names for policy-reporter and use a dedicated
schema: preparation cannot tell whether the selected schema also holds
unrelated objects or identically named tables owned by someone else, and a
rebuild drops the tables its statements resolve, not only the ones it created.

## Large installations

The index is created with an ordinary `CREATE INDEX` inside the preparation
transaction. On a populated child table this blocks writes until preparation
commits, and the build can exceed the pgdriver read timeout: 5 seconds when
`database.timeout` is unset, 10 seconds with the Helm chart default. Raise the
timeout for the rollout, or build the index beforehand:

```sql
CREATE INDEX CONCURRENTLY policy_report_filter_policy_report_id_idx ON policy_report_filter (policy_report_id);
CREATE INDEX CONCURRENTLY policy_report_result_policy_report_id_idx ON policy_report_result (policy_report_id);
CREATE INDEX CONCURRENTLY policy_report_resource_policy_report_id_idx ON policy_report_resource (policy_report_id);
```

Any usable index is reused, so these names are a convenience, not a
requirement. `CONCURRENTLY` cannot run inside a transaction.

An interrupted concurrent build leaves an invalid index, and the next start
fails with `relation ... already exists`. Inspect it (`\d+ policy_report_filter`)
before dropping anything: the index may belong to another tool or be repairable
with `REINDEX INDEX CONCURRENTLY <name>`, so decide case by case.

## Concurrency and limits

Preparation takes one fixed advisory lock before reading the schema version.
Advisory locks are scoped to the current database, so all instances using the
same database serialize, even when they resolve different schemas; instances on
other databases do not wait. Instances running older binaries do not take the
lock and can prepare at the same time.

A waiting instance is bounded by the connection read timeout and fails its start
instead of preparing concurrently; the next start retries.

Tables are resolved through the connection `search_path`, like the rest of the
lifecycle. Set the same `search_path` for every pooled connection and do not
put `pg_temp` first.
