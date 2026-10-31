"""SQLite persistence (RFC §7.8, LLD §3.7).

One connection, used only from the event-loop thread. Calls are synchronous and short, so that
thread is the single writer of the RFC and no locks are needed (LLD L5).
"""

import json
import sqlite3

from .canon import canonical_json
from .model import Envelope

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
  id           TEXT PRIMARY KEY,
  envelope     TEXT NOT NULL,          -- signed release envelope, canonical JSON
  received_at  REAL NOT NULL,          -- local t0
  phase        TEXT NOT NULL           -- RECEIVED|BUILDING|ATTESTED|MISSED|SHED|OBSERVING
);

CREATE TABLE IF NOT EXISTS attestations (  -- only accepted envelopes (§7.4)
  msg_id       TEXT PRIMARY KEY,
  request_id   TEXT NOT NULL REFERENCES requests(id),
  signer       TEXT NOT NULL,
  result       TEXT NOT NULL,
  envelope     TEXT NOT NULL,          -- canonical JSON
  received_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS attestations_req ON attestations(request_id, signer);

CREATE TABLE IF NOT EXISTS my_builds (
  request_id    TEXT PRIMARY KEY REFERENCES requests(id),
  result        TEXT,                  -- hash or FAILED; NULL while building or after ERROR
  artifact_path TEXT,                  -- artifacts/<hash> for a hash result
  error         TEXT,                  -- last ERROR, BAD_REF or BAD_RECIPE reason
  log_path      TEXT,
  started_at    REAL,
  finished_at   REAL
);

CREATE TABLE IF NOT EXISTS evidence (
  id           INTEGER PRIMARY KEY,
  kind         TEXT NOT NULL,          -- EQUIVOCATION|DISAGREE|STALL
  signer       TEXT NOT NULL,
  request_id   TEXT NOT NULL,
  proof        TEXT,                   -- JSON array of envelopes; NULL for STALL
  created_at   REAL NOT NULL,
  UNIQUE (kind, signer, request_id)
);
"""

# upsert_build only ever interpolates names from this set into SQL.
_BUILD_COLUMNS = frozenset(
    {"result", "artifact_path", "error", "log_path", "started_at", "finished_at"}
)


class Store:
    def __init__(self, path: str):
        # isolation_level=None: no implicit transactions; record_own_attestation opens its own.
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")  # a no-op for ":memory:"
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(SCHEMA)

    # --- requests ---------------------------------------------------------------------------

    def add_request(self, rid: str, env: dict, now: float, phase: str) -> bool:
        cur = self.db.execute(
            "INSERT OR IGNORE INTO requests (id, envelope, received_at, phase) VALUES (?,?,?,?)",
            (rid, canonical_json(env).decode(), now, phase),
        )
        return cur.rowcount == 1

    def get_request(self, rid: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()

    def list_requests(self, since: float) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM requests WHERE received_at >= ? ORDER BY received_at, rowid", (since,)
        ).fetchall()

    def live_requests(self, now: float, ttl: int) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM requests WHERE received_at > ? ORDER BY received_at, rowid", (now - ttl,)
        ).fetchall()

    def set_phase(self, rid: str, phase: str) -> None:
        self.db.execute("UPDATE requests SET phase=? WHERE id=?", (phase, rid))

    # --- attestations -----------------------------------------------------------------------

    def add_attestation(self, e: Envelope, now: float) -> bool:
        cur = self.db.execute(*self._insert_attestation(e, now))
        return cur.rowcount == 1

    @staticmethod
    def _insert_attestation(e: Envelope, now: float) -> tuple[str, tuple]:
        return (
            (
                "INSERT OR IGNORE INTO attestations"
                " (msg_id, request_id, signer, result, envelope, received_at)"
                " VALUES (?,?,?,?,?,?)"
            ),
            (
                e.msg_id,
                e.body["request_id"],
                e.signer,
                e.body["result"],
                canonical_json(e.raw).decode(),
                now,
            ),
        )

    def attestation_count(self, rid: str, signer: str) -> int:
        row = self.db.execute(
            "SELECT COUNT(*) FROM attestations WHERE request_id=? AND signer=?", (rid, signer)
        ).fetchone()
        return row[0]

    def attestations(self, rid: str) -> list[dict]:
        rows = self.db.execute(
            "SELECT envelope FROM attestations WHERE request_id=? ORDER BY received_at, rowid",
            (rid,),
        ).fetchall()
        return [json.loads(r["envelope"]) for r in rows]

    # --- own builds -------------------------------------------------------------------------

    def get_build(self, rid: str) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM my_builds WHERE request_id=?", (rid,)).fetchone()

    def upsert_build(self, rid: str, **fields) -> None:
        if not fields.keys() <= _BUILD_COLUMNS:
            raise ValueError(f"unknown my_builds column in {sorted(fields)}")
        self._upsert_build(rid, fields)

    def _upsert_build(self, rid: str, fields: dict) -> None:
        cols = list(fields)
        sets = ", ".join(f"{c}=excluded.{c}" for c in cols) or "request_id=request_id"
        self.db.execute(
            f"INSERT INTO my_builds (request_id{''.join(', ' + c for c in cols)})"
            f" VALUES (?{', ?' * len(cols)}) ON CONFLICT(request_id) DO UPDATE SET {sets}",
            (rid, *fields.values()),
        )

    def record_own_attestation(
        self, rid: str, result: str, artifact_path: str | None, env: Envelope, now: float
    ) -> None:
        """One transaction, committed BEFORE the attestation is broadcast (RFC §7.6 rule 4)."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._upsert_build(
                rid, {"result": result, "artifact_path": artifact_path, "finished_at": now}
            )
            self.db.execute(*self._insert_attestation(env, now))
            self.db.execute("UPDATE requests SET phase='ATTESTED' WHERE id=?", (rid,))
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    def artifact_path(self, sha256: str) -> str | None:
        row = self.db.execute(
            "SELECT artifact_path FROM my_builds WHERE result=? AND artifact_path IS NOT NULL",
            (sha256,),
        ).fetchone()
        return row["artifact_path"] if row else None

    # --- evidence ---------------------------------------------------------------------------

    def add_evidence(
        self, kind: str, signer: str, rid: str, proof: list | None, now: float
    ) -> bool:
        cur = self.db.execute(
            "INSERT OR IGNORE INTO evidence (kind, signer, request_id, proof, created_at)"
            " VALUES (?,?,?,?,?)",
            (kind, signer, rid, None if proof is None else canonical_json(proof).decode(), now),
        )
        return cur.rowcount == 1

    def list_evidence(self, since: float) -> list[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM evidence WHERE created_at >= ? ORDER BY id", (since,)
        ).fetchall()
