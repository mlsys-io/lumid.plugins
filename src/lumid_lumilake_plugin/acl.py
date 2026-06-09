"""SQLite-backed ACL grant store keyed by ``(kind, id, principal_id)``."""

import asyncio
import sqlite3
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path
from typing import Any


class GrantLevel(IntEnum):
    READ = 1
    WRITE = 2


_SCHEMA = """
CREATE TABLE IF NOT EXISTS acl_grants (
    kind TEXT NOT NULL,
    id TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    level INTEGER NOT NULL,
    granted_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (kind, id, principal_id)
);
CREATE INDEX IF NOT EXISTS ix_acl_grants_principal_kind
    ON acl_grants (principal_id, kind);
"""


def _connect(db_path: str | Path) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(db_path),
        check_same_thread=False,
        isolation_level=None,
    )
    conn.executescript(_SCHEMA)
    return conn


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


# Max ``(kind, id)`` pairs per reconcile UPDATE. Each pair binds 2 variables and
# adds one VALUES row, so 400 stays under SQLite's default variable (999) and
# compound-select (500) limits even on the oldest supported builds.
_RECONCILE_CHUNK = 400


class GrantStore:
    """Async CRUD wrapper around the ``acl_grants`` table (single connection, lock-serialised)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._lock = asyncio.Lock()

    async def grant(
        self,
        kind: str,
        resource_id: str,
        principal_id: str,
        level: GrantLevel,
    ) -> None:
        """Upsert; re-granting refreshes ``last_seen_at`` and overwrites ``level``."""
        now = _now_iso()
        params = (kind, resource_id, principal_id, int(level), now, now)
        async with self._lock:
            await asyncio.to_thread(
                self._conn.execute,
                "INSERT INTO acl_grants(kind, id, principal_id, level, granted_at, last_seen_at) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(kind, id, principal_id) "
                "DO UPDATE SET last_seen_at = excluded.last_seen_at, level = excluded.level",
                params,
            )

    async def revoke(self, kind: str, resource_id: str, principal_id: str) -> bool:
        async with self._lock:
            cur = await asyncio.to_thread(
                self._conn.execute,
                "DELETE FROM acl_grants WHERE kind=? AND id=? AND principal_id=?",
                (kind, resource_id, principal_id),
            )
            return cur.rowcount > 0

    async def delete_resource(self, kind: str, resource_id: str) -> int:
        async with self._lock:
            cur = await asyncio.to_thread(
                self._conn.execute,
                "DELETE FROM acl_grants WHERE kind=? AND id=?",
                (kind, resource_id),
            )
            return cur.rowcount

    async def get_level(
        self, kind: str, resource_id: str, principal_id: str
    ) -> GrantLevel | None:
        async with self._lock:
            row = await asyncio.to_thread(
                self._fetchone,
                "SELECT level FROM acl_grants "
                "WHERE kind=? AND id=? AND principal_id=? LIMIT 1",
                (kind, resource_id, principal_id),
            )
        return GrantLevel(row[0]) if row is not None else None

    async def has_grant(
        self, kind: str, resource_id: str, principal_id: str
    ) -> bool:
        return await self.get_level(kind, resource_id, principal_id) is not None

    async def list_ids_for_principal(
        self, principal_id: str, kind: str, min_level: GrantLevel
    ) -> frozenset[str]:
        async with self._lock:
            rows = await asyncio.to_thread(
                self._fetchall,
                "SELECT id FROM acl_grants "
                "WHERE principal_id=? AND kind=? AND level>=?",
                (principal_id, kind, int(min_level)),
            )
        return frozenset(r[0] for r in rows)

    async def reconcile(
        self,
        pairs: Iterable[tuple[str, str]],
        session_start: datetime,
    ) -> tuple[int, int]:
        """Touch live grants, drop stale ones; return ``(touched, deleted)``.

        Deletion is scoped to kinds present in ``pairs`` — kinds absent from a
        sweep (e.g. ``TRACE``/``ARTIFACT`` during a JOB-only call) are
        preserved. Empty ``pairs`` returns ``(0, 0)`` without writing.

        Diverges from the FlowMesh plugin's ``reconcile``, which sweeps all
        kinds in one call and therefore deletes any stale row unconditionally.
        Lumilake invokes ``reconcile_resources`` per-kind, so each call must
        scope its deletions to that kind alone.

        ``session_start`` must be timezone-aware; capture it at plugin-load so
        grants written between load and reconcile survive the sweep.
        """
        if session_start.tzinfo is None:
            raise ValueError("session_start must be timezone-aware")
        materialized = list(pairs)
        async with self._lock:
            return await asyncio.to_thread(
                self._reconcile_sync, materialized, session_start
            )

    def _reconcile_sync(
        self,
        pairs: list[tuple[str, str]],
        session_start: datetime,
    ) -> tuple[int, int]:
        conn = self._conn
        cutoff = session_start.astimezone(UTC).isoformat()
        now = _now_iso()
        # If the input is empty, do nothing: "no resources" is indistinguishable
        # from "we were not asked about this kind", so dropping anything would be
        # unsafe.
        if not pairs:
            return 0, 0
        kinds_seen = list({kind for kind, _ in pairs})
        conn.execute("BEGIN")
        try:
            touched = 0
            for start in range(0, len(pairs), _RECONCILE_CHUNK):
                chunk = pairs[start : start + _RECONCILE_CHUNK]
                values_clause = ",".join("(?, ?)" for _ in chunk)
                flat: list[str] = [now]
                for kind, rid in chunk:
                    flat.extend((kind, rid))
                cur = conn.execute(
                    f"UPDATE acl_grants SET last_seen_at = ? "
                    f"WHERE (kind, id) IN (VALUES {values_clause})",
                    flat,
                )
                touched += cur.rowcount
            # Only drop stale rows for the kinds we were actually asked about.
            # Kinds absent from the input set (e.g. ARTIFACT, TRACE) are left
            # untouched — the server hasn't enumerated those.
            kinds_placeholder = ",".join("?" for _ in kinds_seen)
            cur = conn.execute(
                f"DELETE FROM acl_grants "
                f"WHERE kind IN ({kinds_placeholder}) AND last_seen_at < ?",
                [*kinds_seen, cutoff],
            )
            deleted = cur.rowcount
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return touched, deleted

    def _fetchone(
        self, sql: str, params: tuple[object, ...]
    ) -> tuple[Any, ...] | None:
        row: tuple[Any, ...] | None = self._conn.execute(sql, params).fetchone()
        return row

    def _fetchall(
        self, sql: str, params: tuple[object, ...]
    ) -> list[tuple[Any, ...]]:
        rows: list[tuple[Any, ...]] = self._conn.execute(sql, params).fetchall()
        return rows


def _assert_writable(conn: sqlite3.Connection, db_path: str | Path) -> None:
    """Probe write access by acquiring (and releasing) a RESERVED write lock.

    A deferred ``BEGIN`` would silently succeed on a read-only file because
    SQLite defers write-lock acquisition to the first real write statement;
    ``BEGIN IMMEDIATE`` acquires the lock up front so a read-only file fails
    here rather than at first-write time.
    """
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("ROLLBACK")
    except sqlite3.Error as exc:
        raise RuntimeError(
            f"lumid_lumilake_plugin: ACL DB at {str(db_path)!r} is not "
            "writable. Set LUMID_ACL_DB_PATH to a writable location "
            "or mount /app/plugin-data as a writable volume."
        ) from exc


def open_store_sync(db_path: str | Path) -> GrantStore:
    """Synchronous counterpart to ``open_store``; caller owns the connection lifetime.

    Performs the same writability probe as ``open_store`` so callers don't
    have to repeat it.
    """
    try:
        conn = _connect(db_path)
    except (PermissionError, OSError) as exc:
        raise RuntimeError(
            f"lumid_lumilake_plugin: ACL DB at {str(db_path)!r} is not "
            "writable. Set LUMID_ACL_DB_PATH to a writable location "
            "or mount /app/plugin-data as a writable volume."
        ) from exc
    _assert_writable(conn, db_path)
    return GrantStore(conn)


@asynccontextmanager
async def open_store(db_path: str | Path) -> AsyncIterator[GrantStore]:
    """Open a connection, bootstrap schema, probe writability, yield a ``GrantStore``.

    The writability probe runs at open time so callers can rely on a returned
    store being writable; an unwritable DB raises ``RuntimeError`` here rather
    than at first-write time.
    """
    try:
        conn = await asyncio.to_thread(_connect, db_path)
    except (PermissionError, OSError) as exc:
        raise RuntimeError(
            f"lumid_lumilake_plugin: ACL DB at {str(db_path)!r} is not "
            "writable. Set LUMID_ACL_DB_PATH to a writable location "
            "or mount /app/plugin-data as a writable volume."
        ) from exc
    try:
        await asyncio.to_thread(_assert_writable, conn, db_path)
        yield GrantStore(conn)
    finally:
        await asyncio.to_thread(conn.close)


__all__ = [
    "GrantLevel",
    "GrantStore",
    "open_store",
    "open_store_sync",
]
