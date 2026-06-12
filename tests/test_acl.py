"""Tests for the SQLite-backed GrantStore."""

import sqlite3
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from lumid_flowmesh_plugin.acl import (
    GrantLevel,
    GrantStore,
    open_store,
    open_store_sync,
)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[GrantStore]:
    async with open_store(tmp_path / "acl.sqlite") as s:
        yield s


async def test_grant_and_has_grant_roundtrip(store: GrantStore) -> None:
    await store.grant("workflow", "wf-1", "alice", GrantLevel.WRITE)
    assert await store.has_grant("workflow", "wf-1", "alice") is True
    assert await store.has_grant("workflow", "wf-1", "bob") is False
    assert await store.has_grant("workflow", "missing", "alice") is False


async def test_grant_is_idempotent_per_principal(store: GrantStore) -> None:
    await store.grant("task", "t-1", "alice", GrantLevel.WRITE)
    await store.grant("task", "t-1", "alice", GrantLevel.WRITE)
    assert await store.list_ids_for_principal(
        "alice", "task", GrantLevel.READ
    ) == frozenset({"t-1"})


async def test_get_level_reads_back_grant(store: GrantStore) -> None:
    await store.grant("workflow", "wf-1", "alice", GrantLevel.WRITE)
    assert await store.get_level("workflow", "wf-1", "alice") == GrantLevel.WRITE
    assert await store.get_level("workflow", "wf-1", "bob") is None


async def test_grant_stores_and_overwrites_level(store: GrantStore) -> None:
    await store.grant("workflow", "wf-1", "alice", GrantLevel.READ)
    assert await store.get_level("workflow", "wf-1", "alice") == GrantLevel.READ
    await store.grant("workflow", "wf-1", "alice", GrantLevel.WRITE)
    assert await store.get_level("workflow", "wf-1", "alice") == GrantLevel.WRITE


async def test_regrant_preserves_granted_at_and_bumps_last_seen(
    tmp_path: Path,
) -> None:
    db = tmp_path / "acl.sqlite"
    async with open_store(db) as store:
        await store.grant("workflow", "wf-1", "alice", GrantLevel.READ)
        old = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        with sqlite3.connect(db) as conn:
            conn.execute(
                "UPDATE acl_grants SET granted_at = ?, last_seen_at = ?",
                (old, old),
            )

        await store.grant("workflow", "wf-1", "alice", GrantLevel.WRITE)

        assert _read_granted_at(db, "workflow", "wf-1", "alice") == old
        assert _read_last_seen_at(db, "workflow", "wf-1", "alice") > old
        assert await store.get_level("workflow", "wf-1", "alice") == GrantLevel.WRITE


async def test_list_ids_min_level_filters_by_level(store: GrantStore) -> None:
    await store.grant("workflow", "wf-write", "alice", GrantLevel.WRITE)
    await store.grant("workflow", "wf-read", "alice", GrantLevel.READ)
    assert await store.list_ids_for_principal("alice", "workflow", GrantLevel.READ) == frozenset(
        {"wf-write", "wf-read"}
    )
    assert await store.list_ids_for_principal(
        "alice", "workflow", GrantLevel.WRITE
    ) == frozenset({"wf-write"})


async def test_multiple_principals_share_a_resource(store: GrantStore) -> None:
    await store.grant("workflow", "wf-1", "alice", GrantLevel.WRITE)
    await store.grant("workflow", "wf-1", "bob", GrantLevel.WRITE)
    assert await store.has_grant("workflow", "wf-1", "alice") is True
    assert await store.has_grant("workflow", "wf-1", "bob") is True


async def test_revoke_removes_single_grant(store: GrantStore) -> None:
    await store.grant("workflow", "wf-1", "alice", GrantLevel.WRITE)
    await store.grant("workflow", "wf-1", "bob", GrantLevel.WRITE)
    assert await store.revoke("workflow", "wf-1", "alice") is True
    assert await store.has_grant("workflow", "wf-1", "alice") is False
    assert await store.has_grant("workflow", "wf-1", "bob") is True
    assert await store.revoke("workflow", "wf-1", "alice") is False


async def test_delete_resource_removes_all_grants(store: GrantStore) -> None:
    await store.grant("worker", "w-1", "alice", GrantLevel.WRITE)
    await store.grant("worker", "w-1", "bob", GrantLevel.WRITE)
    await store.grant("worker", "w-2", "alice", GrantLevel.WRITE)
    assert await store.delete_resource("worker", "w-1") == 2
    assert await store.has_grant("worker", "w-1", "alice") is False
    assert await store.has_grant("worker", "w-1", "bob") is False
    assert await store.has_grant("worker", "w-2", "alice") is True
    assert await store.delete_resource("worker", "w-1") == 0


async def test_list_ids_for_principal_filters_by_kind_and_principal(
    store: GrantStore,
) -> None:
    await store.grant("workflow", "wf-1", "alice", GrantLevel.WRITE)
    await store.grant("workflow", "wf-2", "alice", GrantLevel.WRITE)
    await store.grant("workflow", "wf-3", "bob", GrantLevel.WRITE)
    await store.grant("task", "t-1", "alice", GrantLevel.WRITE)

    assert await store.list_ids_for_principal("alice", "workflow", GrantLevel.READ) == frozenset(
        {"wf-1", "wf-2"}
    )
    assert await store.list_ids_for_principal(
        "alice", "task", GrantLevel.READ
    ) == frozenset({"t-1"})
    assert await store.list_ids_for_principal("alice", "worker", GrantLevel.READ) == frozenset()


async def test_list_ids_includes_resources_shared_with_principal(
    store: GrantStore,
) -> None:
    await store.grant("workflow", "wf-1", "alice", GrantLevel.WRITE)
    await store.grant("workflow", "wf-1", "bob", GrantLevel.WRITE)
    await store.grant("workflow", "wf-2", "bob", GrantLevel.WRITE)
    assert await store.list_ids_for_principal("bob", "workflow", GrantLevel.READ) == frozenset(
        {"wf-1", "wf-2"}
    )


async def test_reconcile_marks_live_and_drops_stale(tmp_path: Path) -> None:
    db = tmp_path / "acl.sqlite"
    async with open_store(db) as store:
        await store.grant("worker", "live", "alice", GrantLevel.WRITE)
        await store.grant("worker", "live", "bob", GrantLevel.WRITE)
        await store.grant("worker", "stale", "alice", GrantLevel.WRITE)
        _backdate_all(db, "worker", "live", days=120)
        _backdate_all(db, "worker", "stale", days=120)

        session_start = datetime.now(UTC)
        touched, deleted = await store.reconcile(
            [("worker", "live")], session_start
        )
        assert touched == 2  # both alice and bob refreshed
        assert deleted == 1  # stale dropped

        assert await store.has_grant("worker", "live", "alice") is True
        assert await store.has_grant("worker", "live", "bob") is True
        assert await store.has_grant("worker", "stale", "alice") is False


async def test_reconcile_empty_batch_wipes_pre_session_rows(
    tmp_path: Path,
) -> None:
    db = tmp_path / "acl.sqlite"
    async with open_store(db) as store:
        await store.grant("workflow", "wf-1", "alice", GrantLevel.WRITE)
        _backdate_all(db, "workflow", "wf-1", days=1)

        session_start = datetime.now(UTC)
        touched, deleted = await store.reconcile([], session_start)

        assert touched == 0
        assert deleted == 1
        assert await store.has_grant("workflow", "wf-1", "alice") is False


async def test_reconcile_preserves_grants_written_after_session_start(
    store: GrantStore,
) -> None:
    """A grant written after `session_start` survives even with an empty
    batch — its `last_seen_at` is past the cutoff. This protects grants from
    `register` calls that land between plugin install and the host's
    reconcile sweep.
    """
    session_start = datetime.now(UTC) - timedelta(seconds=1)
    await store.grant("worker", "fresh", "alice", GrantLevel.WRITE)
    touched, deleted = await store.reconcile([], session_start)
    assert (touched, deleted) == (0, 0)
    assert await store.has_grant("worker", "fresh", "alice") is True


async def test_reconcile_on_empty_store_is_noop(store: GrantStore) -> None:
    session_start = datetime.now(UTC)
    touched, deleted = await store.reconcile(
        [("worker", "w-1")], session_start
    )
    assert (touched, deleted) == (0, 0)


async def test_reconcile_rejects_naive_session_start(store: GrantStore) -> None:
    """A tz-naive cutoff would compare lexically wrong against the UTC
    `last_seen_at` strings and fail open, so the store rejects it outright."""
    with pytest.raises(ValueError, match="timezone-aware"):
        await store.reconcile([], datetime.now())  # naive on purpose


async def test_reconcile_normalises_non_utc_session_start(tmp_path: Path) -> None:
    """A non-UTC aware cutoff is normalised to UTC before comparison, so a
    grant whose `last_seen_at` equals `session_start` (same instant, different
    zone) is not falsely swept by a lexical string mismatch."""
    db = tmp_path / "acl.sqlite"
    async with open_store(db) as store:
        await store.grant("workflow", "wf-1", "alice", GrantLevel.WRITE)
        instant = datetime(2026, 1, 1, tzinfo=UTC)
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE acl_grants SET last_seen_at = ?", (instant.isoformat(),))

        # Same instant expressed in +08:00 — its raw isoformat is lexically
        # larger than the stored UTC string, which would wrongly delete the row
        # without UTC normalisation.
        session_start = instant.astimezone(timezone(timedelta(hours=8)))
        touched, deleted = await store.reconcile([], session_start)

        assert (touched, deleted) == (0, 0)
        assert await store.has_grant("workflow", "wf-1", "alice") is True


async def test_reconcile_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "acl.sqlite"
    async with open_store(db) as store:
        await store.grant("worker", "w-1", "alice", GrantLevel.WRITE)
        _backdate_all(db, "worker", "w-1", days=120)

        session_start = datetime.now(UTC)
        first = await store.reconcile([("worker", "w-1")], session_start)
        second = await store.reconcile([("worker", "w-1")], session_start)

        assert first == (1, 0)
        assert second == (1, 0)
        assert await store.has_grant("worker", "w-1", "alice") is True


async def test_reconcile_rolls_back_on_error(tmp_path: Path) -> None:
    """If the DELETE raises after the UPDATE ran, the UPDATE is rolled back
    too — `last_seen_at` stays at its pre-reconcile value."""
    db = tmp_path / "acl.sqlite"
    async with open_store(db) as store:
        await store.grant("worker", "w-1", "alice", GrantLevel.WRITE)
        _backdate_all(db, "worker", "w-1", days=120)
        original_last_seen_at = _read_last_seen_at(db, "worker", "w-1", "alice")

        real_conn = store._conn

        class _ExplodingConn:
            def __init__(self) -> None:
                self.calls = 0

            def execute(self, sql: str, *args: object) -> sqlite3.Cursor:
                self.calls += 1
                # Let BEGIN (1) and UPDATE (2) run on the real connection;
                # raise on DELETE (3) so the except clause issues ROLLBACK
                # and the UPDATE's bump to `last_seen_at` is reverted.
                if self.calls == 3:
                    raise RuntimeError("simulated mid-transaction failure")
                return real_conn.execute(sql, *args)

        store._conn = _ExplodingConn()  # type: ignore[assignment]
        try:
            session_start = datetime.now(UTC)
            with pytest.raises(RuntimeError, match="simulated"):
                await store.reconcile([("worker", "w-1")], session_start)
        finally:
            store._conn = real_conn

        assert await store.has_grant("worker", "w-1", "alice") is True
        assert _read_last_seen_at(db, "worker", "w-1", "alice") == original_last_seen_at


async def test_open_store_is_idempotent(tmp_path: Path) -> None:
    db = tmp_path / "acl.sqlite"
    async with open_store(db) as _store:
        pass
    async with open_store(db) as _store:  # second open must not raise
        pass


async def test_open_store_creates_missing_parent_dirs(tmp_path: Path) -> None:
    db = tmp_path / "nested" / "dirs" / "acl.sqlite"
    assert not db.parent.exists()
    async with open_store(db) as store:
        await store.grant("workflow", "wf-1", "alice", GrantLevel.WRITE)
        assert await store.has_grant("workflow", "wf-1", "alice") is True
    assert db.exists()


async def test_open_store_rejects_readonly_path(tmp_path: Path) -> None:
    ro_dir = tmp_path / "ro"
    ro_dir.mkdir()
    db = ro_dir / "acl.sqlite"
    async with open_store(db) as _store:  # create the file first
        pass
    db.chmod(0o400)
    ro_dir.chmod(0o500)
    try:
        with pytest.raises(RuntimeError, match=r"lumid_flowmesh_plugin: ACL DB.*not writable"):
            async with open_store(db) as _store:
                pass
    finally:
        ro_dir.chmod(0o700)
        db.chmod(0o600)


def test_open_store_sync_rejects_readonly_path(tmp_path: Path) -> None:
    ro_dir = tmp_path / "ro_sync"
    ro_dir.mkdir()
    db = ro_dir / "acl.sqlite"
    open_store_sync(db).close()  # create the file first
    db.chmod(0o400)
    ro_dir.chmod(0o500)
    try:
        with pytest.raises(RuntimeError, match=r"lumid_flowmesh_plugin: ACL DB.*not writable"):
            open_store_sync(db)
    finally:
        ro_dir.chmod(0o700)
        db.chmod(0o600)


def _backdate_all(db_path: Path, kind: str, resource_id: str, *, days: int) -> None:
    backdated = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE acl_grants SET last_seen_at = ? WHERE kind = ? AND id = ?",
            (backdated, kind, resource_id),
        )


def _read_granted_at(
    db_path: Path, kind: str, resource_id: str, principal_id: str
) -> str:
    return _read_column(db_path, "granted_at", kind, resource_id, principal_id)


def _read_last_seen_at(
    db_path: Path, kind: str, resource_id: str, principal_id: str
) -> str:
    return _read_column(db_path, "last_seen_at", kind, resource_id, principal_id)


def _read_column(
    db_path: Path, column: str, kind: str, resource_id: str, principal_id: str
) -> str:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            f"SELECT {column} FROM acl_grants "
            "WHERE kind = ? AND id = ? AND principal_id = ?",
            (kind, resource_id, principal_id),
        ).fetchone()
    assert row is not None
    return str(row[0])
