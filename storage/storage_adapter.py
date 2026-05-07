"""Scalable storage adapter for XDR hot data, audit logs and history."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


VALID_TABLES = {"hot_events", "incidents", "audit_logs", "telemetry_history"}


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    hot_events_days: int = 14
    incidents_days: int = 365
    audit_logs_days: int = 365
    telemetry_history_days: int = 30

    def days_for(self, table: str) -> int:
        return {
            "hot_events": self.hot_events_days,
            "incidents": self.incidents_days,
            "audit_logs": self.audit_logs_days,
            "telemetry_history": self.telemetry_history_days,
        }[_table(table)]


@dataclass(frozen=True, slots=True)
class StorageRecord:
    tenant_id: str
    record_id: str
    host_id: str
    timestamp: str
    category: str
    payload: dict[str, Any]
    created_at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SQLiteStorageAdapter:
    """SQLite implementation used by local, demo and CI deployments."""

    schema_version = 1

    def __init__(self, db_path: str | Path, *, retention: RetentionPolicy | None = None):
        self.db_path = Path(db_path)
        self.retention = retention or RetentionPolicy()
        self._lock = threading.RLock()
        self.init_schema()

    def init_schema(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_sqlite_schema())
            conn.execute(
                "INSERT OR IGNORE INTO storage_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (self.schema_version, "scalable_xdr_storage_v1", _now_iso()),
            )

    @contextmanager
    def _conn(self):
        with self._lock:
            conn = sqlite3.connect(str(self.db_path), timeout=10.0)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def write_hot_event(self, tenant_id: str, event: dict[str, Any]) -> str:
        return self._write_record("hot_events", tenant_id, event)

    def write_telemetry_history(self, tenant_id: str, event: dict[str, Any]) -> str:
        return self._write_record("telemetry_history", tenant_id, event)

    def write_incident(self, tenant_id: str, incident: dict[str, Any]) -> str:
        return self._write_record("incidents", tenant_id, incident)

    def write_audit_log(self, tenant_id: str, audit_log: dict[str, Any]) -> str:
        return self._write_record("audit_logs", tenant_id, audit_log)

    def query_hot_events(
        self,
        *,
        tenant_id: str,
        host_id: str | None = None,
        limit: int = 100,
        since_iso: str | None = None,
    ) -> list[StorageRecord]:
        return self.query_records("hot_events", tenant_id=tenant_id, host_id=host_id, limit=limit, since_iso=since_iso)

    def query_records(
        self,
        table: str,
        *,
        tenant_id: str,
        host_id: str | None = None,
        limit: int = 100,
        since_iso: str | None = None,
    ) -> list[StorageRecord]:
        table = _table(table)
        tenant = _tenant_required(tenant_id)
        query = f"SELECT * FROM {table} WHERE tenant_id = ?"
        params: list[Any] = [tenant]
        if host_id:
            query += " AND host_id = ?"
            params.append(str(host_id))
        if since_iso:
            query += " AND timestamp >= ?"
            params.append(str(since_iso))
        query += " ORDER BY timestamp DESC, created_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 5000)))
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [_row_to_record(row) for row in rows]

    def cleanup_retention(self, *, now: datetime | None = None) -> dict[str, int]:
        now_dt = now or datetime.now(timezone.utc)
        deleted: dict[str, int] = {}
        with self._conn() as conn:
            for table in sorted(VALID_TABLES):
                cutoff = (now_dt - timedelta(days=max(1, self.retention.days_for(table)))).timestamp()
                cur = conn.execute(f"DELETE FROM {table} WHERE created_at < ?", (cutoff,))
                deleted[table] = int(cur.rowcount or 0)
        return deleted

    def migration_status(self) -> dict[str, Any]:
        with self._conn() as conn:
            rows = conn.execute("SELECT version, name, applied_at FROM storage_migrations ORDER BY version").fetchall()
        versions = [int(row["version"]) for row in rows]
        return {
            "backend": "sqlite",
            "schema_version": max(versions, default=0),
            "latest_supported": self.schema_version,
            "pending": max(0, self.schema_version - max(versions, default=0)),
            "migrations": [dict(row) for row in rows],
        }

    def stats(self) -> dict[str, Any]:
        with self._conn() as conn:
            counts = {
                table: int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in sorted(VALID_TABLES)
            }
        return {"backend": "sqlite", "tables": counts, "db_path": str(self.db_path)}

    def close(self) -> None:
        return None

    def _write_record(self, table: str, tenant_id: str, payload: dict[str, Any]) -> str:
        table = _table(table)
        tenant = _tenant_required(tenant_id)
        clean_payload = dict(payload or {})
        record_id = str(clean_payload.get("record_id") or clean_payload.get("event_id") or clean_payload.get("incident_id") or f"rec_{uuid.uuid4().hex}")
        host_id = str(clean_payload.get("host_id") or "")
        timestamp = str(clean_payload.get("timestamp") or _now_iso())
        category = str(clean_payload.get("event_type") or clean_payload.get("category") or clean_payload.get("severity") or "general")[:80]
        text = json.dumps(clean_payload, ensure_ascii=True, separators=(",", ":"), default=str)
        with self._conn() as conn:
            conn.execute(
                f"""
                INSERT OR REPLACE INTO {table}
                    (tenant_id, record_id, host_id, timestamp, category, payload_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant, record_id, host_id, timestamp, category, text, time.time()),
            )
        return record_id


class PostgresStorageAdapter:
    """PostgreSQL-ready implementation with lazy driver import."""

    schema_version = 1

    def __init__(self, dsn: str, *, retention: RetentionPolicy | None = None):
        if not dsn:
            raise ValueError("postgres_dsn_required")
        self.dsn = dsn
        self.retention = retention or RetentionPolicy()
        self._lock = threading.RLock()
        self.init_schema()

    @contextmanager
    def _conn(self):
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError as exc:  # pragma: no cover - depends on prod driver
            raise RuntimeError("psycopg2 is required for PostgresStorageAdapter") from exc
        with self._lock:
            conn = psycopg2.connect(self.dsn)
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def init_schema(self) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(_postgres_schema())
                cur.execute(
                    """
                    INSERT INTO storage_migrations(version, name, applied_at)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (version) DO NOTHING
                    """,
                    (self.schema_version, "scalable_xdr_storage_v1", _now_iso()),
                )

    def write_hot_event(self, tenant_id: str, event: dict[str, Any]) -> str:
        return self._write_record("hot_events", tenant_id, event)

    def write_telemetry_history(self, tenant_id: str, event: dict[str, Any]) -> str:
        return self._write_record("telemetry_history", tenant_id, event)

    def write_incident(self, tenant_id: str, incident: dict[str, Any]) -> str:
        return self._write_record("incidents", tenant_id, incident)

    def write_audit_log(self, tenant_id: str, audit_log: dict[str, Any]) -> str:
        return self._write_record("audit_logs", tenant_id, audit_log)

    def query_hot_events(self, *, tenant_id: str, host_id: str | None = None, limit: int = 100, since_iso: str | None = None) -> list[StorageRecord]:
        return self.query_records("hot_events", tenant_id=tenant_id, host_id=host_id, limit=limit, since_iso=since_iso)

    def query_records(self, table: str, *, tenant_id: str, host_id: str | None = None, limit: int = 100, since_iso: str | None = None) -> list[StorageRecord]:
        table = _table(table)
        tenant = _tenant_required(tenant_id)
        query = f"SELECT * FROM {table} WHERE tenant_id = %s"
        params: list[Any] = [tenant]
        if host_id:
            query += " AND host_id = %s"
            params.append(str(host_id))
        if since_iso:
            query += " AND timestamp >= %s"
            params.append(str(since_iso))
        query += " ORDER BY timestamp DESC, created_at DESC LIMIT %s"
        params.append(max(1, min(int(limit), 5000)))
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                columns = [desc[0] for desc in cur.description]
                rows = [dict(zip(columns, row)) for row in cur.fetchall()]
        return [_row_to_record(row) for row in rows]

    def cleanup_retention(self, *, now: datetime | None = None) -> dict[str, int]:
        now_dt = now or datetime.now(timezone.utc)
        deleted: dict[str, int] = {}
        with self._conn() as conn:
            with conn.cursor() as cur:
                for table in sorted(VALID_TABLES):
                    cutoff = (now_dt - timedelta(days=max(1, self.retention.days_for(table)))).timestamp()
                    cur.execute(f"DELETE FROM {table} WHERE created_at < %s", (cutoff,))
                    deleted[table] = int(cur.rowcount or 0)
        return deleted

    def migration_status(self) -> dict[str, Any]:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version, name, applied_at FROM storage_migrations ORDER BY version")
                rows = cur.fetchall()
        versions = [int(row[0]) for row in rows]
        return {
            "backend": "postgres",
            "schema_version": max(versions, default=0),
            "latest_supported": self.schema_version,
            "pending": max(0, self.schema_version - max(versions, default=0)),
            "migrations": [{"version": row[0], "name": row[1], "applied_at": row[2]} for row in rows],
        }

    def close(self) -> None:
        return None

    def _write_record(self, table: str, tenant_id: str, payload: dict[str, Any]) -> str:
        table = _table(table)
        tenant = _tenant_required(tenant_id)
        clean_payload = dict(payload or {})
        record_id = str(clean_payload.get("record_id") or clean_payload.get("event_id") or clean_payload.get("incident_id") or f"rec_{uuid.uuid4().hex}")
        host_id = str(clean_payload.get("host_id") or "")
        timestamp = str(clean_payload.get("timestamp") or _now_iso())
        category = str(clean_payload.get("event_type") or clean_payload.get("category") or clean_payload.get("severity") or "general")[:80]
        text = json.dumps(clean_payload, ensure_ascii=True, separators=(",", ":"), default=str)
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    INSERT INTO {table}
                        (tenant_id, record_id, host_id, timestamp, category, payload_json, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, record_id) DO UPDATE SET
                        host_id = EXCLUDED.host_id,
                        timestamp = EXCLUDED.timestamp,
                        category = EXCLUDED.category,
                        payload_json = EXCLUDED.payload_json,
                        created_at = EXCLUDED.created_at
                    """,
                    (tenant, record_id, host_id, timestamp, category, text, time.time()),
                )
        return record_id


def get_storage_adapter(backend: str = "sqlite", **kwargs: Any) -> SQLiteStorageAdapter | PostgresStorageAdapter:
    backend = (backend or "sqlite").lower()
    if backend == "sqlite":
        return SQLiteStorageAdapter(**kwargs)
    if backend in {"postgres", "postgresql", "pg"}:
        return PostgresStorageAdapter(**kwargs)
    raise ValueError(f"unknown storage backend: {backend!r}")


def _sqlite_schema() -> str:
    table_sql = "\n".join(_sqlite_table(table) for table in sorted(VALID_TABLES))
    return f"""
    CREATE TABLE IF NOT EXISTS storage_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
    );
    {table_sql}
    """


def _sqlite_table(table: str) -> str:
    table = _table(table)
    return f"""
    CREATE TABLE IF NOT EXISTS {table} (
        tenant_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
        host_id TEXT NOT NULL DEFAULT '',
        timestamp TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'general',
        payload_json TEXT NOT NULL,
        created_at REAL NOT NULL,
        PRIMARY KEY (tenant_id, record_id)
    );
    CREATE INDEX IF NOT EXISTS idx_{table}_tenant_ts ON {table}(tenant_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_{table}_tenant_host_ts ON {table}(tenant_id, host_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_{table}_created_at ON {table}(created_at);
    """


def _postgres_schema() -> str:
    table_sql = "\n".join(_postgres_table(table) for table in sorted(VALID_TABLES))
    return f"""
    CREATE TABLE IF NOT EXISTS storage_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
    );
    {table_sql}
    """


def _postgres_table(table: str) -> str:
    table = _table(table)
    return f"""
    CREATE TABLE IF NOT EXISTS {table} (
        tenant_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
        host_id TEXT NOT NULL DEFAULT '',
        timestamp TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'general',
        payload_json TEXT NOT NULL,
        created_at DOUBLE PRECISION NOT NULL,
        PRIMARY KEY (tenant_id, record_id)
    );
    CREATE INDEX IF NOT EXISTS idx_{table}_tenant_ts ON {table}(tenant_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_{table}_tenant_host_ts ON {table}(tenant_id, host_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_{table}_created_at ON {table}(created_at);
    """


def _row_to_record(row: Any) -> StorageRecord:
    if not isinstance(row, dict):
        row = dict(row)
    try:
        payload = json.loads(row.get("payload_json") or "{}")
    except json.JSONDecodeError:
        payload = {"decode_error": True}
    return StorageRecord(
        tenant_id=str(row.get("tenant_id") or ""),
        record_id=str(row.get("record_id") or ""),
        host_id=str(row.get("host_id") or ""),
        timestamp=str(row.get("timestamp") or ""),
        category=str(row.get("category") or ""),
        payload=payload,
        created_at=float(row.get("created_at") or 0.0),
    )


def _table(value: str) -> str:
    table = str(value or "").strip()
    if table not in VALID_TABLES:
        raise ValueError("invalid_storage_table")
    return table


def _tenant_required(value: str | None) -> str:
    tenant = str(value or "").strip()
    if not tenant:
        raise ValueError("tenant_id_required")
    return tenant


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
