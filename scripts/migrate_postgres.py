"""PostgreSQL migration runner for SAFE production deployments."""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MIGRATIONS_DIR = ROOT / "migrations" / "postgres"
MIGRATION_RE = re.compile(r"^(?P<version>\d{3,})_(?P<name>[a-z0-9_]+)\.sql$")


@dataclass(frozen=True)
class Migration:
    version: str
    name: str
    path: Path
    sql: str

    @property
    def filename(self) -> str:
        return self.path.name


def discover_migrations(migrations_dir: str | Path = DEFAULT_MIGRATIONS_DIR) -> list[Migration]:
    base = Path(migrations_dir)
    migrations: list[Migration] = []
    if not base.exists():
        raise FileNotFoundError(f"migrations directory not found: {base}")
    for path in base.glob("*.sql"):
        match = MIGRATION_RE.match(path.name)
        if not match:
            continue
        migrations.append(
            Migration(
                version=match.group("version"),
                name=match.group("name"),
                path=path,
                sql=path.read_text(encoding="utf-8").strip() + "\n",
            )
        )
    migrations.sort(key=lambda item: (int(item.version), item.filename))
    versions = [item.version for item in migrations]
    if len(versions) != len(set(versions)):
        raise ValueError("duplicate migration version detected")
    return migrations


def ensure_schema_migrations_sql() -> str:
    return """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL DEFAULT '',
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
""".strip()


def pending_migrations(migrations: Sequence[Migration], applied_versions: Iterable[str]) -> list[Migration]:
    applied = {str(version) for version in applied_versions}
    return [migration for migration in migrations if migration.version not in applied]


def get_applied_versions(connection) -> set[str]:
    with connection.cursor() as cursor:
        cursor.execute(ensure_schema_migrations_sql())
        cursor.execute("SELECT version FROM schema_migrations ORDER BY version")
        return {str(row[0]) for row in cursor.fetchall()}


def apply_migrations(connection, migrations: Sequence[Migration], *, dry_run: bool = False) -> list[str]:
    if dry_run:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT version FROM schema_migrations ORDER BY version")
                applied = {str(row[0]) for row in cursor.fetchall()}
        except Exception:
            applied = set()
        return [migration.filename for migration in pending_migrations(migrations, applied)]

    applied = get_applied_versions(connection)
    applied_files: list[str] = []
    for migration in pending_migrations(migrations, applied):
        with connection.cursor() as cursor:
            cursor.execute(migration.sql)
            cursor.execute(
                """
                INSERT INTO schema_migrations(version, name, checksum)
                VALUES (%s, %s, %s)
                ON CONFLICT (version) DO NOTHING
                """,
                (migration.version, migration.name, _checksum(migration.sql)),
            )
        connection.commit()
        applied_files.append(migration.filename)
    return applied_files


def connect(database_url: str):
    try:
        import psycopg2  # type: ignore
    except ImportError as exc:  # pragma: no cover - dependency is declared in requirements.
        raise RuntimeError("psycopg2-binary is required to run PostgreSQL migrations") from exc
    return psycopg2.connect(database_url)


def _checksum(sql: str) -> str:
    import hashlib

    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply SAFE PostgreSQL migrations.")
    parser.add_argument("--database-url", default=os.environ.get("DATABASE_URL", ""))
    parser.add_argument("--migrations-dir", default=str(DEFAULT_MIGRATIONS_DIR))
    parser.add_argument("--dry-run", action="store_true", help="List pending migrations without applying them.")
    args = parser.parse_args(argv)

    if not args.database_url:
        print("DATABASE_URL is required. Pass --database-url or set env DATABASE_URL.", file=sys.stderr)
        return 2

    migrations = discover_migrations(args.migrations_dir)
    with connect(args.database_url) as connection:
        applied = apply_migrations(connection, migrations, dry_run=args.dry_run)

    verb = "Pending" if args.dry_run else "Applied"
    print(f"{verb} migrations: {len(applied)}")
    for filename in applied:
        print(f" - {filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
