"""FlowMesh ``GrantStore``: the shared CRUD base plus an all-kinds reconcile sweep.

FlowMesh runs its startup reconcile once with every live resource across all
kinds, so the sweep refreshes ``last_seen_at`` on every listed pair and then
drops any grant left untouched.
"""

import asyncio
from collections.abc import Iterable
from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from pathlib import Path

from ._core import GrantLevel
from ._core import GrantStore as _CoreGrantStore
from ._core import open_store as _core_open_store
from ._core import open_store_sync as _core_open_store_sync

_PLUGIN_NAME = "lumid_flowmesh_plugin"


class GrantStore(_CoreGrantStore):
    async def reconcile(
        self,
        pairs: Iterable[tuple[str, str]],
        session_start: datetime,
    ) -> tuple[int, int]:
        """Replace the store's live set with the listed ``(kind, id)`` pairs.

        Single atomic transaction: bumps ``last_seen_at`` to ``now`` for every
        grant matching a pair, then deletes every grant whose ``last_seen_at``
        is older than ``session_start``. Returns ``(touched, deleted)``.

        ``session_start`` is the cutoff used to recognise stale rows. Callers
        capture it at plugin-load time so grants written between load and the
        host's reconcile call survive the sweep. It must be timezone-aware
        (naive is rejected) for lexical comparison.
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
        now = self._now_iso()
        conn.execute("BEGIN")
        try:
            touched = 0
            reconcile_chunk = self.RECONCILE_CHUNK
            for start in range(0, len(pairs), reconcile_chunk):
                chunk = pairs[start : start + reconcile_chunk]
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
            cur = conn.execute(
                "DELETE FROM acl_grants WHERE last_seen_at < ?", (cutoff,)
            )
            deleted = cur.rowcount
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return touched, deleted


def open_store_sync(db_path: str | Path) -> GrantStore:
    """Open a FlowMesh ``GrantStore`` synchronously; caller owns its lifetime."""
    return _core_open_store_sync(db_path, GrantStore, _PLUGIN_NAME)


def open_store(db_path: str | Path) -> AbstractAsyncContextManager[GrantStore]:
    """Open a connection, bootstrap the schema, yield a ``GrantStore``; close on exit."""
    return _core_open_store(db_path, GrantStore, _PLUGIN_NAME)


__all__ = [
    "GrantLevel",
    "GrantStore",
    "open_store",
    "open_store_sync",
]
