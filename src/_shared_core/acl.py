"""SQLite-backed grant store shared by lum.id host plugins.

One table, ``acl_grants``, keyed by ``(kind, id, principal_id)``. Each row is
one grant: principal P holds ``level`` access on (kind, id). ``level`` is an
ordinal — ``READ`` (1) permits read, ``WRITE`` (2) permits read and mutation.
Rows are written by a ``ResourceRegistrar`` at resource-creation time (owner
gets ``WRITE``) and read by a ``PermissionChecker`` on every authz decision.
``granted_at`` records when the grant was first written; ``last_seen_at`` is the
liveness marker the reconcile sweep refreshes and compares against.

This module is host-neutral. It owns the CRUD surface and the connection
lifecycle — schema bootstrap, parent-dir creation, and a writability probe so a
missing directory or read-only ``LUMID_ACL_DB_PATH`` fails loudly at open time
rather than cryptically at first write. The ``reconcile`` sweep is intentionally
left to each plugin's ``GrantStore`` subclass: hosts differ on whether a sweep
covers every kind in one call or one kind per call, and that difference cannot
be reconciled into a single default.

Built on the stdlib ``sqlite3`` module. A single ``Connection`` opened in
autocommit is shared across all ops; an ``asyncio.Lock`` serialises access and
each query runs in ``asyncio.to_thread`` so the event loop never blocks.
"""

import asyncio
import sqlite3
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager, suppress
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


def _not_writable_error(db_path: str | Path, plugin_name: str) -> RuntimeError:
    return RuntimeError(
        f"{plugin_name}: ACL DB at {str(db_path)!r} is not writable. "
        "Set LUMID_ACL_DB_PATH to a writable location or mount "
        "/app/plugin-data as a writable volume."
    )


def _assert_writable(
    conn: sqlite3.Connection, db_path: str | Path, plugin_name: str
) -> None:
    """Probe write access with a header write that is immediately rolled back.

    ``BEGIN IMMEDIATE`` alone only takes a RESERVED lock, which SQLite grants
    even on a read-only file, so it does not detect read-only DBs. Issuing an
    actual write (``PRAGMA user_version``) inside the transaction forces the
    ``attempt to write a readonly database`` error up front, rather than at
    first real write inside a request. The ``ROLLBACK`` leaves no trace.
    """
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("PRAGMA user_version = 0")
        conn.execute("ROLLBACK")
    except sqlite3.Error as exc:
        with suppress(sqlite3.Error):
            conn.execute("ROLLBACK")
        raise _not_writable_error(db_path, plugin_name) from exc


class GrantStore:
    """Async CRUD wrapper around the ``acl_grants`` table.

    All access goes through ``asyncio.to_thread`` and is serialised by an
    ``asyncio.Lock`` since a single ``sqlite3.Connection`` is not thread-safe.

    ``reconcile`` is host-specific and is left abstract here — each plugin's
    subclass implements it (see ``RECONCILE_CHUNK`` and ``_now_iso`` for the
    building blocks subclasses reuse).
    """

    # Max ``(kind, id)`` pairs a reconcile UPDATE may bind. Each pair binds 2
    # variables and adds one VALUES row, so 400 stays under SQLite's default
    # variable (999) and compound-select (500) limits even on the oldest builds.
    RECONCILE_CHUNK = 400

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._lock = asyncio.Lock()

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(UTC).isoformat()

    def close(self) -> None:
        """Close the underlying sqlite connection. Caller-owned lifecycle."""
        self._conn.close()

    async def grant(
        self,
        kind: str,
        resource_id: str,
        principal_id: str,
        level: GrantLevel,
    ) -> None:
        """Upsert a grant for ``(kind, resource_id, principal_id)`` with ``now``.

        Re-granting refreshes ``last_seen_at`` and overwrites ``level``.
        """
        now = self._now_iso()
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
        """Remove a single grant. Returns True if a row was removed."""
        async with self._lock:
            cur = await asyncio.to_thread(
                self._conn.execute,
                "DELETE FROM acl_grants WHERE kind=? AND id=? AND principal_id=?",
                (kind, resource_id, principal_id),
            )
            return cur.rowcount > 0

    async def delete_resource(self, kind: str, resource_id: str) -> int:
        """Remove every grant for ``(kind, resource_id)``. Returns rows removed."""
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
        """Return ``principal_id``'s grant level on ``(kind, resource_id)``, or None."""
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
        """Return True if ``principal_id`` has any grant on ``(kind, resource_id)``."""
        return await self.get_level(kind, resource_id, principal_id) is not None

    async def list_ids_for_principal(
        self, principal_id: str, kind: str, min_level: GrantLevel
    ) -> frozenset[str]:
        """Return ids of ``kind`` that ``principal_id`` holds ``>= min_level`` on."""
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

        Host-specific — the deletion scope differs per host, so each plugin's
        ``GrantStore`` subclass overrides this. ``session_start`` is the
        staleness cutoff and must be timezone-aware.
        """
        raise NotImplementedError(
            "reconcile is host-specific; override it in the plugin's "
            "GrantStore subclass"
        )

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


def open_store_sync[S: GrantStore](
    db_path: str | Path, store_cls: type[S], plugin_name: str
) -> S:
    """Open a connection, bootstrap the schema, probe writability, return a store.

    Caller owns the connection lifetime (call ``store.close()`` when done).
    ``store_cls`` is the plugin's ``GrantStore`` subclass; ``plugin_name`` tags
    the error raised when the DB path is not writable.
    """
    try:
        conn = _connect(db_path)
    except (PermissionError, OSError) as exc:
        raise _not_writable_error(db_path, plugin_name) from exc
    try:
        _assert_writable(conn, db_path, plugin_name)
    except Exception:
        conn.close()
        raise
    return store_cls(conn)


@asynccontextmanager
async def open_store[S: GrantStore](
    db_path: str | Path, store_cls: type[S], plugin_name: str
) -> AsyncIterator[S]:
    """Async wrapper around ``open_store_sync``: opens the connection in a
    thread, yields the store, and closes the connection on exit."""
    store = await asyncio.to_thread(open_store_sync, db_path, store_cls, plugin_name)
    try:
        yield store
    finally:
        await asyncio.to_thread(store.close)


__all__ = [
    "GrantLevel",
    "GrantStore",
    "open_store",
    "open_store_sync",
]
