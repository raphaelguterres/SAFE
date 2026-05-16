from __future__ import annotations

from pathlib import Path

from scripts.migrate_postgres import apply_migrations, discover_migrations, ensure_schema_migrations_sql, pending_migrations


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, sql, params=None):
        self.connection.executed.append((sql, params))
        normalized = " ".join(sql.lower().split())
        if normalized.startswith("select version from schema_migrations"):
            self.rows = [(version,) for version in sorted(self.connection.applied)]
        elif normalized.startswith("insert into schema_migrations") and params:
            self.connection.applied.add(params[0])

    def fetchall(self):
        return list(self.rows)


class FakeConnection:
    def __init__(self, applied=None):
        self.applied = set(applied or [])
        self.executed = []
        self.commits = 0

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.commits += 1


def test_discover_migrations_orders_by_numeric_prefix():
    migrations = discover_migrations()

    assert [migration.version for migration in migrations][:3] == ["001", "002", "003"]
    assert migrations[0].filename == "001_init_core.sql"


def test_pending_migrations_filters_applied_versions():
    migrations = discover_migrations()

    pending = pending_migrations(migrations, {"001"})

    assert [migration.version for migration in pending] == ["002", "003"]


def test_apply_migrations_is_idempotent_with_schema_table():
    migrations = discover_migrations()
    connection = FakeConnection(applied={"001", "002", "003"})

    applied = apply_migrations(connection, migrations)

    assert applied == []
    assert connection.commits == 0
    assert any("schema_migrations" in sql for sql, _params in connection.executed)


def test_apply_migrations_applies_only_missing_and_records_versions():
    migrations = discover_migrations()
    connection = FakeConnection(applied={"001"})

    applied = apply_migrations(connection, migrations)

    assert applied == ["002_multi_tenant_indexes.sql", "003_security_data_platform.sql"]
    assert connection.applied == {"001", "002", "003"}
    assert connection.commits == 2


def test_dry_run_lists_pending_without_mutation():
    migrations = discover_migrations()
    connection = FakeConnection(applied={"001"})

    pending = apply_migrations(connection, migrations, dry_run=True)

    assert pending == ["002_multi_tenant_indexes.sql", "003_security_data_platform.sql"]
    assert connection.applied == {"001"}
    assert connection.commits == 0


def test_schema_migrations_sql_is_stable():
    sql = ensure_schema_migrations_sql()

    assert "CREATE TABLE IF NOT EXISTS schema_migrations" in sql
    assert "version TEXT PRIMARY KEY" in sql
