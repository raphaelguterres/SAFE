"""
Transporte HTTPS com retry exponencial e buffer offline em disco.

Decisões de design:

- requests + urllib3.Retry: padrão de mercado, sem dependência exótica.
  Backoff exponencial cobre rede instável; status 5xx/429 dispara retry.

- Buffer offline em SQLite (não JSON file): grava append-only com
  sqlite3 stdlib (zero dep extra), sobrevive a SIGKILL no meio da
  escrita, e tem rotação automática (drop dos mais antigos quando
  passa de offline_buffer_max). JSON-on-disk teria que cuidar de
  fsync, lock e corruption manualmente — não vale.

- Idempotência: cada evento já carrega event_id (gerado no collector).
  Re-envio depois de timeout duplica no DB do servidor? Não — o
  servidor faz INSERT OR IGNORE em event_id (já vimos em demo_seed
  _save_raw). Então é seguro re-tentar em caso de "timeout MAS server
  pode ter recebido".

- API key NUNCA aparece em log. Mesmo em DEBUG, mascara prefixo
  primeiros 8 chars + '...' (mesmo padrão de alguns SDKs cloud).

- Não fazemos validate cert pinning aqui (verify_tls=true confia no
  CA bundle do sistema). Pinning fica como follow-up se precisar.
"""

from __future__ import annotations

import base64
import gzip
import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger("netguard.agent.sender")


def _mask_key(key: str) -> str:
    if not key:
        return "<empty>"
    if len(key) <= 8:
        return "***"
    return key[:8] + "..." + str(len(key))


def chunk_envelope(envelope: dict, max_events: int = 100) -> list[dict]:
    """Split large envelopes without changing the event schema."""
    events = envelope.get("events") or []
    max_events = max(1, int(max_events))
    if not isinstance(events, list) or len(events) <= max_events:
        return [dict(envelope)]
    chunks = []
    total = (len(events) + max_events - 1) // max_events
    for index in range(0, len(events), max_events):
        chunk = dict(envelope)
        chunk["events"] = events[index:index + max_events]
        chunk["batch_index"] = len(chunks)
        chunk["batch_total"] = total
        chunks.append(chunk)
    return chunks


def compressed_payload_preview(payload: dict) -> dict:
    """Prepare a gzip+base64 payload for future compatible transports."""
    raw = json.dumps(payload, default=str, separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(raw)
    return {
        "compressed": True,
        "encoding": "gzip+base64",
        "payload": base64.b64encode(compressed).decode("ascii"),
        "original_bytes": len(raw),
        "compressed_bytes": len(compressed),
    }


# ── Buffer offline ────────────────────────────────────────────────

_BUFFER_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_json TEXT NOT NULL,
    created_at   REAL NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_pending_created
    ON pending_events(created_at);
"""


class OfflineBuffer:
    """
    SQLite append-only com cap. Drop oldest quando estoura cap.
    Thread-safe (uma conexão + lock interno).
    """

    def __init__(self, db_path: Path, max_events: int = 5000, max_payload_bytes: int = 2_000_000):
        self.db_path = db_path
        self.max_events = max(100, int(max_events))
        self.max_payload_bytes = max(64_000, int(max_payload_bytes))
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.executescript(_BUFFER_SCHEMA)

    @contextmanager
    def _conn(self):
        with self._lock:
            conn = sqlite3.connect(str(self.db_path), timeout=5.0)
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    def push(self, payload: dict) -> bool:
        text = json.dumps(payload, default=str)
        payload_bytes = len(text.encode("utf-8"))
        if payload_bytes > self.max_payload_bytes:
            logger.error(
                "Payload excede limite do buffer offline (%d bytes > %d)",
                payload_bytes,
                self.max_payload_bytes,
            )
            return False
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO pending_events (payload_json, created_at, attempts) "
                "VALUES (?, ?, 0)",
                (text, time.time()),
            )
            # Rotação: se passou do cap, deleta os mais antigos.
            count = conn.execute(
                "SELECT COUNT(*) FROM pending_events"
            ).fetchone()[0]
            if count > self.max_events:
                excess = count - self.max_events
                conn.execute(
                    "DELETE FROM pending_events WHERE id IN ("
                    "SELECT id FROM pending_events ORDER BY id ASC LIMIT ?"
                    ")",
                    (excess,),
                )
                logger.warning(
                    "Buffer rotacionado: drop %d evento(s) mais antigos",
                    excess,
                )
        return True

    def pop_batch(self, max_items: int = 50) -> list[tuple[int, dict]]:
        """Devolve (rowid, payload). Caller chama ack() depois do POST OK."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, payload_json FROM pending_events "
                "ORDER BY id ASC LIMIT ?",
                (max_items,),
            ).fetchall()
        out = []
        for rid, text in rows:
            try:
                out.append((rid, json.loads(text)))
            except json.JSONDecodeError:
                # Linha corrompida — ack pra remover do queue.
                logger.warning("Pending row %s corrompida — descartando", rid)
                self.ack([rid])
        return out

    def ack(self, ids: list[int]) -> int:
        if not ids:
            return 0
        with self._conn() as conn:
            placeholders = ",".join("?" * len(ids))
            cur = conn.execute(
                f"DELETE FROM pending_events WHERE id IN ({placeholders})",
                ids,
            )
            return cur.rowcount or 0

    def increment_attempt(self, ids: list[int]) -> None:
        if not ids:
            return
        with self._conn() as conn:
            placeholders = ",".join("?" * len(ids))
            conn.execute(
                f"UPDATE pending_events SET attempts = attempts + 1 "
                f"WHERE id IN ({placeholders})",
                ids,
            )

    def size(self) -> int:
        with self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM pending_events"
            ).fetchone()[0]

    def stats(self) -> dict:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(attempts), 0), COALESCE(MIN(created_at), 0) FROM pending_events"
            ).fetchone()
        return {
            "size": int(row[0] or 0),
            "max_events": self.max_events,
            "max_attempts": int(row[1] or 0),
            "oldest_created_at": float(row[2] or 0),
            "max_payload_bytes": self.max_payload_bytes,
        }


# ── HTTP sender ───────────────────────────────────────────────────


class EventSender:
    """
    POSTa eventos pro /api/events com retry + buffer offline.

    Uso:
        sender = EventSender(server_url, api_key, ...)
        ok = sender.send_batch(envelope)  # True se entregue, False se buffered

    Em background, run_drain_loop() esvazia o buffer quando o server
    voltar online.
    """

    def __init__(
        self,
        server_url: str,
        api_key: str,
        *,
        verify_tls: bool = True,
        timeout: int = 15,
        buffer_path: Path | str = "agent_buffer.db",
        offline_buffer_max: int = 5000,
        max_events_per_batch: int = 100,
        offline_max_payload_bytes: int = 2_000_000,
        compression_enabled: bool = False,
        max_retries: int = 4,
        backoff_factor: float = 0.8,
    ):
        self.server_url = server_url
        self.api_key = api_key
        self.verify_tls = bool(verify_tls)
        self.timeout = int(timeout)
        self.max_retries = int(max_retries)
        self.backoff_factor = float(backoff_factor)
        self.max_events_per_batch = max(1, int(max_events_per_batch))
        self.compression_enabled = bool(compression_enabled)
        self.buffer = OfflineBuffer(Path(buffer_path),
                                     max_events=offline_buffer_max,
                                     max_payload_bytes=offline_max_payload_bytes)
        self._stop_drain = threading.Event()
        self._session = self._build_session()

    def _build_session(self):
        # Import tardio pra agente sem requests não morrer no import.
        try:
            import requests
            from urllib3.util.retry import Retry
            from requests.adapters import HTTPAdapter
        except ImportError:
            logger.error(
                "requests não instalado — sender em modo degraded. "
                "Instale: pip install requests"
            )
            return None

        retry = Retry(
            total=self.max_retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["POST"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session = requests.Session()
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _headers(self) -> dict:
        return {
            "Content-Type": "application/json",
            "User-Agent": "SAFE-Agent/1.0",
            "X-API-Key": self.api_key,
            "X-NetGuard-Agent-Key": self.api_key,
        }

    def _post(self, payload: dict) -> tuple[bool, str]:
        if self._session is None:
            return False, "requests not installed"
        try:
            resp = self._session.post(
                self.server_url,
                json=payload,
                headers=self._headers(),
                timeout=self.timeout,
                verify=self.verify_tls,
            )
        except Exception as exc:
            return False, f"network error: {exc.__class__.__name__}"
        if resp.status_code in (200, 201, 202):
            return True, f"ok status={resp.status_code}"
        # 4xx raramente é transitório (auth ruim, schema inválido).
        # Logamos detalhadamente uma vez e dropamos do retry.
        body = (resp.text or "")[:300]
        return False, f"http {resp.status_code}: {body}"

    def _should_buffer_failure(self, info: str, *, buffer_on_failure: bool) -> bool:
        if not buffer_on_failure:
            return False
        msg = (info or "").lower()
        if msg.startswith("http 4") and not msg.startswith("http 429"):
            return False
        return True

    def send_batch(self, envelope: dict, *, buffer_on_failure: bool = True) -> bool:
        """
        Envia envelope { host_id, hostname, agent_version, events: [...] }.
        Se falhar por erro transitório, persiste no buffer e devolve False.
        """
        chunks = chunk_envelope(envelope, self.max_events_per_batch)
        if len(chunks) > 1:
            all_ok = True
            for chunk in chunks:
                all_ok = self.send_batch(chunk, buffer_on_failure=buffer_on_failure) and all_ok
            return all_ok

        ok, info = self._post(envelope)
        if ok:
            logger.debug(
                "POST OK | events=%d | key=%s",
                len(envelope.get("events") or []),
                _mask_key(self.api_key),
            )
            return True

        if not self._should_buffer_failure(info, buffer_on_failure=buffer_on_failure):
            logger.error(
                "POST rejeitado sem retry offline (%s) | events=%d",
                info, len(envelope.get("events") or []),
            )
            return False

        logger.warning(
            "POST falhou (%s) — bufferizando %d evento(s)",
            info, len(envelope.get("events") or []),
        )
        self.buffer.push(envelope)
        return False

    def buffer_stats(self) -> dict:
        return self.buffer.stats()

    def drain_once(self, max_batches: int = 5) -> int:
        """
        Tenta esvaziar o buffer. Retorna quantos lotes drenados.
        Para cedo se algum POST falhar (server ainda offline).
        """
        drained = 0
        for _ in range(max_batches):
            batch = self.buffer.pop_batch(max_items=1)
            if not batch:
                break
            rid, payload = batch[0]
            ok, info = self._post(payload)
            if ok:
                self.buffer.ack([rid])
                drained += 1
            else:
                self.buffer.increment_attempt([rid])
                logger.debug("Drain interrompido: %s", info)
                break
        return drained

    def run_drain_loop(self, interval: float = 30.0) -> None:
        """Loop blocking — chame em thread separada se quiser background."""
        logger.info("Drain loop iniciado (interval=%ss)", interval)
        while not self._stop_drain.is_set():
            try:
                if self.buffer.size() > 0:
                    self.drain_once()
            except Exception as exc:
                logger.exception("drain loop error: %s", exc)
            self._stop_drain.wait(interval)

    def stop_drain(self) -> None:
        self._stop_drain.set()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    s = EventSender(
        server_url="http://127.0.0.1:5000/api/events",
        api_key="nga_TEST_KEY_DO_NOT_USE",
        verify_tls=False,
        buffer_path="/tmp/agent_buffer_test.db",
    )
    print("buffer size:", s.buffer.size())
