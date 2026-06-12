"""Lumilake ``GrantStore``: the shared CRUD base plus a per-kind reconcile sweep.

Lumilake invokes ``reconcile_resources`` once per kind, so each sweep must scope
its deletions to the kinds present in the input — kinds absent from a call (e.g.
``TRACE``/``ARTIFACT`` during a JOB-only sweep) must be preserved. (FlowMesh
reconciles every kind in one call and drops untouched grants unconditionally;
that divergence is why ``reconcile`` lives in the subclass rather than the
shared base.)
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

_PLUGIN_NAME = "lumid_lumilake_plugin"


class GrantStore(_CoreGrantStore):
    async def reconcile(
        self,
        pairs: Iterable[tuple[str, str]],
        session_start: datetime,
    ) -> tuple[int, int]:
        """Touch live grants, drop stale ones; return ``(touched, deleted)``.

        Deletion is scoped to kinds present in ``pairs`` — kinds absent from a
        sweep (e.g. ``TRACE``/``ARTIFACT`` during a JOB-only call) are
        preserved. Empty ``pairs`` returns ``(0, 0)`` without writing.

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
        now = self._now_iso()
        # If the input is empty, do nothing: "no resources" is indistinguishable
        # from "we were not asked about this kind", so dropping anything would be
        # unsafe.
        if not pairs:
            return 0, 0
        kinds_seen = list({kind for kind, _ in pairs})
        conn.execute("BEGIN")
        try:
            touched = 0
            for start in range(0, len(pairs), self.RECONCILE_CHUNK):
                chunk = pairs[start : start + self.RECONCILE_CHUNK]
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


def open_store_sync(db_path: str | Path) -> GrantStore:
    """Open a Lumilake ``GrantStore`` synchronously; caller owns its lifetime."""
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
