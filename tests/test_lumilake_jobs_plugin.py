"""Tests for lumid_lumilake_plugin."""

import logging
import sqlite3
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException
from lumid_hooks import PrincipalContext, ResourceRef
from lumilake_hook import BaseBindings, ResourceAction, ResourceKind

import lumid_lumilake_plugin._core.acl as core_acl
from lumid_lumilake_plugin import install
from lumid_lumilake_plugin.acl import GrantLevel, GrantStore, open_store, open_store_sync
from lumid_lumilake_plugin.permissions import LumidPermissionChecker
from lumid_lumilake_plugin.registrar import LumidResourceRegistrar

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _principal(pid: str, *scopes: str) -> PrincipalContext:
    return PrincipalContext(
        principal_id=pid,
        org_id="lumid",
        external_id=pid,
        principal_type="user",
        scopes=list(scopes),
    )


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[GrantStore]:
    async with open_store(tmp_path / "acl.sqlite") as s:
        yield s


@pytest.fixture
def log() -> logging.Logger:
    return logging.getLogger("lumid_lumilake_plugin.tests")


JOB = ResourceKind.JOB.value
READ = ResourceAction.READ.value
WRITE = ResourceAction.WRITE.value
CANCEL = ResourceAction.CANCEL.value
ADMIN = ResourceAction.ADMIN.value


# ---------------------------------------------------------------------------
# install()
# ---------------------------------------------------------------------------


async def test_install_returns_basebindings_with_checker_and_registrar(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:

    monkeypatch.setenv("LUMID_ACL_DB_PATH", str(tmp_path / "acl.sqlite"))
    async with install() as bindings:
        assert isinstance(bindings, BaseBindings)
        assert len(bindings.permission_checkers) == 1
        assert len(bindings.resource_registrars) == 1
        assert isinstance(bindings.permission_checkers[0], LumidPermissionChecker)
        assert isinstance(bindings.resource_registrars[0], LumidResourceRegistrar)


# ---------------------------------------------------------------------------
# LumidPermissionChecker — admin bypass
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("admin_scope", ["*", "lumilake:*", "lumilake:admin", "flowmesh:admin"])
async def test_admin_bypass_all_actions(
    store: GrantStore, log: logging.Logger, admin_scope: str
) -> None:
    checker = LumidPermissionChecker(store)
    await checker.require(_principal("alice", admin_scope), ResourceRef(kind=JOB), READ, log)
    await checker.require(
        _principal("alice", admin_scope), ResourceRef(kind=JOB, id="j-1"), WRITE, log
    )
    assert await checker.accessible_ids(_principal("alice", admin_scope), JOB, READ, log) is None


# ---------------------------------------------------------------------------
# LumidPermissionChecker — kind-level scope checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "action,scope",
    [
        (READ, "lumilake:jobs:read"),
        (WRITE, "lumilake:jobs:write"),
        (CANCEL, "lumilake:jobs:cancel"),
    ],
)
async def test_kind_level_scope_grants_access(
    store: GrantStore, log: logging.Logger, action: str, scope: str
) -> None:
    checker = LumidPermissionChecker(store)
    await checker.require(_principal("alice", scope), ResourceRef(kind=JOB), action, log)


async def test_kind_level_read_scope_does_not_allow_write(
    store: GrantStore, log: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    with pytest.raises(HTTPException) as exc:
        await checker.require(
            _principal("alice", "lumilake:jobs:read"), ResourceRef(kind=JOB), WRITE, log
        )
    assert exc.value.status_code == 403


async def test_kind_level_no_scope_denies(store: GrantStore, log: logging.Logger) -> None:
    checker = LumidPermissionChecker(store)
    with pytest.raises(HTTPException) as exc:
        await checker.require(_principal("alice"), ResourceRef(kind=JOB), READ, log)
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# LumidPermissionChecker — concrete-id grant checks
# ---------------------------------------------------------------------------


async def test_concrete_id_with_grant_allowed(store: GrantStore, log: logging.Logger) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(JOB, "j-1", "alice", GrantLevel.WRITE)
    for action in (READ, WRITE, CANCEL):
        await checker.require(_principal("alice"), ResourceRef(kind=JOB, id="j-1"), action, log)


async def test_concrete_id_without_scope_or_grant_denied(
    store: GrantStore, log: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    with pytest.raises(HTTPException) as exc:
        await checker.require(_principal("alice"), ResourceRef(kind=JOB, id="j-99"), READ, log)
    assert exc.value.status_code == 403


async def test_concrete_id_non_owner_denied(store: GrantStore, log: logging.Logger) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(JOB, "j-1", "alice", GrantLevel.WRITE)
    with pytest.raises(HTTPException) as exc:
        await checker.require(_principal("bob"), ResourceRef(kind=JOB, id="j-1"), READ, log)
    assert exc.value.status_code == 403


async def test_concrete_id_admin_action_is_admin_only(
    store: GrantStore, log: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(JOB, "j-1", "alice", GrantLevel.WRITE)
    with pytest.raises(HTTPException) as exc:
        await checker.require(_principal("alice"), ResourceRef(kind=JOB, id="j-1"), ADMIN, log)
    assert exc.value.status_code == 403
    assert "admin-only" in exc.value.detail


# ---------------------------------------------------------------------------
# LumidResourceRegistrar — happy paths
# ---------------------------------------------------------------------------


async def test_registrar_register_writes_grant(store: GrantStore, log: logging.Logger) -> None:

    reg = LumidResourceRegistrar(store, datetime.now(UTC))
    await reg.register(_principal("alice"), ResourceRef(kind=JOB, id="j-1"), log)
    assert await store.has_grant(JOB, "j-1", "alice") is True


async def test_registrar_deregister_removes_all_grants(
    store: GrantStore, log: logging.Logger
) -> None:

    reg = LumidResourceRegistrar(store, datetime.now(UTC))
    await reg.register(_principal("alice"), ResourceRef(kind=JOB, id="j-1"), log)
    await store.grant(JOB, "j-1", "bob", GrantLevel.WRITE)
    await reg.deregister(_principal("alice"), ResourceRef(kind=JOB, id="j-1"), log)
    assert await store.has_grant(JOB, "j-1", "alice") is False
    assert await store.has_grant(JOB, "j-1", "bob") is False


async def test_registrar_reconcile_drops_stale_resources(
    tmp_path: Path, log: logging.Logger
) -> None:

    db_path = tmp_path / "acl.sqlite"
    async with open_store(db_path) as s:
        reg = LumidResourceRegistrar(s, datetime.now(UTC))
        await s.grant(JOB, "live", "alice", GrantLevel.WRITE)
        await s.grant(JOB, "stale", "alice", GrantLevel.WRITE)
        # Backdate both rows so they look old.
        backdated = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        with sqlite3.connect(db_path) as conn:
            conn.execute("UPDATE acl_grants SET last_seen_at = ?", (backdated,))

        await reg.reconcile([ResourceRef(kind=JOB, id="live")], log)

        assert await s.has_grant(JOB, "live", "alice") is True
        assert await s.has_grant(JOB, "stale", "alice") is False


async def test_registrar_kind_level_register_is_noop(
    store: GrantStore, log: logging.Logger, caplog: pytest.LogCaptureFixture
) -> None:

    reg = LumidResourceRegistrar(store, datetime.now(UTC))
    with caplog.at_level(logging.WARNING):
        await reg.register(_principal("alice"), ResourceRef(kind=JOB), log)
    assert "kind-level register" in caplog.text
    assert await store.list_ids_for_principal("alice", JOB, GrantLevel.READ) == frozenset()


# ---------------------------------------------------------------------------
# Finding 1 — parent-dir creation and install-time writability check
# ---------------------------------------------------------------------------


async def test_install_creates_parent_dir_when_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_path = tmp_path / "nested" / "subdir" / "acl.sqlite"
    monkeypatch.setenv("LUMID_ACL_DB_PATH", str(db_path))
    async with install():
        pass
    assert db_path.exists()
    assert db_path.parent.is_dir()


async def test_install_raises_when_parent_unwritable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    db_path = tmp_path / "nested" / "acl.sqlite"
    monkeypatch.setenv("LUMID_ACL_DB_PATH", str(db_path))

    original_mkdir = Path.mkdir

    def _failing_mkdir(self: Path, *args: object, **kwargs: object) -> None:
        raise PermissionError("read-only filesystem")

    monkeypatch.setattr(Path, "mkdir", _failing_mkdir)
    with pytest.raises(RuntimeError, match="LUMID_ACL_DB_PATH"):
        async with install():
            pass

    monkeypatch.setattr(Path, "mkdir", original_mkdir)


async def test_install_raises_when_db_exists_but_unwritable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A pre-existing read-only DB must fail at install time, not fail open.

    The writability probe runs a rolled-back header write
    (``PRAGMA user_version``) inside an IMMEDIATE transaction. A plain
    ``BEGIN IMMEDIATE`` would not catch a read-only DB: it only takes a RESERVED
    lock, which SQLite grants even on a read-only file, so the actual write is
    what surfaces the error.

    sqlite3.Connection is a C extension type whose instance attributes are
    read-only slots — instance-level method replacement is not possible.
    The test hands sqlite3.connect()'s ``factory`` a subclass that overrides
    execute() to raise OperationalError on the probe's header write, a
    deterministic read-only simulation independent of filesystem permissions.

    The patch targets lumid_lumilake_plugin._core.acl._connect (the shared
    factory the plugin's open_store actually calls) so only the second call
    (from install()) gets the failing factory; the first call (from
    open_store_sync() in test setup) must succeed to bootstrap the schema.
    """
    class _ReadOnlyConn(sqlite3.Connection):
        """sqlite3.Connection subclass that rejects the probe's header write.

        Mirrors a real read-only DB: ``BEGIN IMMEDIATE`` succeeds (RESERVED lock
        only), but the ``PRAGMA user_version`` write fails. The positional-only
        ``parameters: object`` signature matches the arity of the real
        sqlite3.Connection.execute stub while accepting any value; the
        # type: ignore[arg-type] on the super() call is needed because ``object``
        is wider than SupportsLenAndGetItem | Mapping; at runtime sqlite3 accepts
        () as the default without complaint.
        """

        def execute(
            self,
            sql: str,
            parameters: object = (),
            /,
        ) -> sqlite3.Cursor:
            if sql.strip().upper().startswith("PRAGMA USER_VERSION ="):
                raise sqlite3.OperationalError("attempt to write a readonly database")
            return super().execute(sql, parameters)  # type: ignore[arg-type]

    db_path = tmp_path / "existing_acl.sqlite"
    monkeypatch.setenv("LUMID_ACL_DB_PATH", str(db_path))

    # Bootstrap the schema so the DB file exists before install() is called.
    open_store_sync(db_path)
    assert db_path.exists(), "pre-condition: DB must exist before the probe"

    def _patched_connect(path: object) -> sqlite3.Connection:
        # Every call through this patch uses the read-only-simulating subclass.
        # The schema-bootstrap open_store_sync() call in the test setup runs
        # BEFORE the patch is installed, so it goes through the real _connect.
        Path(path).parent.mkdir(parents=True, exist_ok=True)  # type: ignore[arg-type]
        conn = sqlite3.connect(
            str(path),
            check_same_thread=False,
            isolation_level=None,
            factory=_ReadOnlyConn,
        )
        conn.executescript(core_acl._SCHEMA)
        return conn

    monkeypatch.setattr(core_acl, "_connect", _patched_connect)

    with pytest.raises(RuntimeError, match="LUMID_ACL_DB_PATH"):
        async with install():
            pass


# ---------------------------------------------------------------------------
# Finding 2 — reconcile scoped to kinds present in input set
# ---------------------------------------------------------------------------


async def test_reconcile_scoped_to_input_kinds(tmp_path: Path, log: logging.Logger) -> None:
    # Verifies two properties in one sweep:
    # 1. Stale grants within an input kind (j-2) are dropped.
    # 2. Grants for kinds absent from the input (ARTIFACT, TRACE) are untouched.
    ARTIFACT = ResourceKind.ARTIFACT.value
    TRACE = ResourceKind.TRACE.value
    db_path = tmp_path / "acl.sqlite"
    async with open_store(db_path) as s:
        reg = LumidResourceRegistrar(s, datetime.now(UTC))
        await s.grant(JOB, "j-1", "alice", GrantLevel.WRITE)
        await s.grant(JOB, "j-2", "alice", GrantLevel.WRITE)
        await s.grant(ARTIFACT, "a-1", "alice", GrantLevel.WRITE)
        await s.grant(TRACE, "t-1", "alice", GrantLevel.WRITE)

        backdated = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        with sqlite3.connect(db_path) as conn:
            conn.execute("UPDATE acl_grants SET last_seen_at = ?", (backdated,))

        # Reconcile with only j-1; j-2 is stale within the JOB kind.
        await reg.reconcile([ResourceRef(kind=JOB, id="j-1")], log)

        assert await s.has_grant(JOB, "j-1", "alice") is True  # present in input — survives
        assert await s.has_grant(JOB, "j-2", "alice") is False  # absent from input — dropped
        assert await s.has_grant(ARTIFACT, "a-1", "alice") is True  # kind not in input — untouched
        assert await s.has_grant(TRACE, "t-1", "alice") is True  # kind not in input — untouched


async def test_reconcile_empty_input_is_noop(tmp_path: Path, log: logging.Logger) -> None:
    db_path = tmp_path / "acl.sqlite"
    async with open_store(db_path) as s:
        reg = LumidResourceRegistrar(s, datetime.now(UTC))
        await s.grant(JOB, "j-1", "alice", GrantLevel.WRITE)

        backdated = (datetime.now(UTC) - timedelta(days=30)).isoformat()
        with sqlite3.connect(db_path) as conn:
            conn.execute("UPDATE acl_grants SET last_seen_at = ?", (backdated,))

        await reg.reconcile([], log)

        assert await s.has_grant(JOB, "j-1", "alice") is True


# ---------------------------------------------------------------------------
# open_store writability probe (moved out of install())
# ---------------------------------------------------------------------------


async def test_open_store_async_raises_when_db_unwritable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The writability probe lives in ``open_store`` itself so every caller
    (install + future direct callers) benefits without duplicating the probe."""
    class _ReadOnlyConn(sqlite3.Connection):
        def execute(
            self,
            sql: str,
            parameters: object = (),
            /,
        ) -> sqlite3.Cursor:
            if sql.strip().upper().startswith("PRAGMA USER_VERSION ="):
                raise sqlite3.OperationalError("attempt to write a readonly database")
            return super().execute(sql, parameters)  # type: ignore[arg-type]

    db_path = tmp_path / "ro_acl.sqlite"
    # Bootstrap schema with the real _connect first.
    open_store_sync(db_path)

    def _patched_connect(path: object) -> sqlite3.Connection:
        Path(path).parent.mkdir(parents=True, exist_ok=True)  # type: ignore[arg-type]
        conn = sqlite3.connect(
            str(path),
            check_same_thread=False,
            isolation_level=None,
            factory=_ReadOnlyConn,
        )
        conn.executescript(core_acl._SCHEMA)
        return conn

    monkeypatch.setattr(core_acl, "_connect", _patched_connect)

    with pytest.raises(RuntimeError, match="LUMID_ACL_DB_PATH"):
        async with open_store(db_path):
            pass


async def test_open_store_closes_connection_on_exit(tmp_path: Path) -> None:
    """The async context manager must close the connection when the ``with``
    block exits so file handles don't leak across the FastAPI lifespan."""
    db_path = tmp_path / "lifecycle.sqlite"
    async with open_store(db_path) as store:
        # Sanity: store is usable inside the block.
        assert await store.has_grant(JOB, "j-x", "alice") is False
        held = store
    # After exit the underlying connection is closed; any DB op raises
    # sqlite3.ProgrammingError("Cannot operate on a closed database.").
    with pytest.raises(sqlite3.ProgrammingError):
        held._conn.execute("SELECT 1")


def test_grant_store_close_is_idempotent_via_double_close(
    tmp_path: Path,
) -> None:
    """``GrantStore.close()`` is exposed for callers that own a sync store
    (``open_store_sync``). It hands the close down to the sqlite connection;
    calling it twice should not raise — sqlite tolerates double close."""
    store = open_store_sync(tmp_path / "close.sqlite")
    store.close()
    store.close()


# --- Lumilake fleet kinds ------------------------------------------------------
# routes/workers.py enumerates the FlowMesh fleet through Lumilake with the same
# two-stage shape FlowMesh uses: require_permission(WORKER, None, READ) then
# resolve_accessible_ids(WORKER, READ). Without a kind-level scope the first stage
# 403s every non-admin; with the scope but no fleet_kinds the second silently
# empties the list, which is the worse failure because nothing logs it.

import logging as _logging

import pytest as _pytest
from lumid_hooks import PrincipalContext as _PrincipalContext
from lumilake_hook import ResourceAction as _RA
from lumilake_hook import ResourceKind as _RK
from lumid_hooks import ResourceRef as _ResourceRef

from lumid_lumilake_plugin.acl import GrantLevel as _GL
from lumid_lumilake_plugin.acl import open_store as _open_store
from lumid_lumilake_plugin.permissions import LumidPermissionChecker as _Checker


def _p(pid: str, *scopes: str) -> _PrincipalContext:
    return _PrincipalContext(
        principal_id=pid, org_id="lumid", external_id=pid,
        principal_type="user", scopes=list(scopes),
    )


@_pytest.fixture
async def _ll_store(tmp_path):
    async with _open_store(tmp_path / "ll-acl.sqlite") as s:
        yield s


async def test_lumilake_worker_scope_passes_kind_level_gate(_ll_store) -> None:
    """`lumilake:workers:read` must clear require(); without it, admin-only."""
    c = _Checker(_ll_store)
    log = _logging.getLogger("t")
    ref = _ResourceRef(kind=_RK.WORKER.value, id=None)
    await c.require(_p("alice", "lumilake:workers:read"), ref, _RA.READ.value, log)
    with _pytest.raises(Exception):
        await c.require(_p("bob"), ref, _RA.READ.value, log)


async def test_lumilake_workers_not_ownership_filtered(_ll_store) -> None:
    """Holding the scope yields the whole fleet, not an empty list."""
    c = _Checker(_ll_store)
    log = _logging.getLogger("t")
    await _ll_store.grant(_RK.WORKER.value, "wkr-1", "fleet", _GL.WRITE)
    got = await c.accessible_ids(_p("alice", "lumilake:workers:read"), _RK.WORKER.value, _RA.READ.value, log)
    assert got is None, "worker list must not be ownership-filtered"
    # and no scope and no grant still means no rows -- not a public read
    assert await c.accessible_ids(_p("alice"), _RK.WORKER.value, _RA.READ.value, log) == frozenset()


async def test_lumilake_jobs_still_ownership_filtered(_ll_store) -> None:
    """Tenancy boundary: the jobs scope must NOT reveal another principal's jobs."""
    c = _Checker(_ll_store)
    log = _logging.getLogger("t")
    await _ll_store.grant(_RK.JOB.value, "job-alice", "alice", _GL.READ)
    await _ll_store.grant(_RK.JOB.value, "job-bob", "bob", _GL.READ)
    got = await c.accessible_ids(_p("alice", "lumilake:jobs:read"), _RK.JOB.value, _RA.READ.value, log)
    assert got == frozenset({"job-alice"}), "jobs must stay per-principal"


async def test_lumilake_worker_concrete_read_follows_scope(_ll_store) -> None:
    """The scope that lists the fleet also reads one worker by id; without it, 403."""
    c = _Checker(_ll_store)
    log = _logging.getLogger("t")
    await _ll_store.grant(_RK.WORKER.value, "wkr-1", "fleet", _GL.WRITE)
    ref = _ResourceRef(kind=_RK.WORKER.value, id="wkr-1")
    await c.require(_p("alice", "lumilake:workers:read"), ref, _RA.READ.value, log)
    with _pytest.raises(HTTPException) as exc:
        await c.require(_p("alice"), ref, _RA.READ.value, log)
    assert exc.value.status_code == 403
    with _pytest.raises(HTTPException) as exc:
        await c.require(_p("alice", "lumilake:workers:read"), ref, _RA.WRITE.value, log)
    assert exc.value.status_code == 403


async def test_lumilake_job_concrete_read_still_needs_grant(_ll_store) -> None:
    """The fleet exception must not leak to jobs: the jobs scope reads only your own."""
    c = _Checker(_ll_store)
    log = _logging.getLogger("t")
    await _ll_store.grant(_RK.JOB.value, "job-bob", "bob", _GL.READ)
    ref = _ResourceRef(kind=_RK.JOB.value, id="job-bob")
    with _pytest.raises(HTTPException) as exc:
        await c.require(_p("alice", "lumilake:jobs:read"), ref, _RA.READ.value, log)
    assert exc.value.status_code == 403


# --- Claim-on-first-use for OBJECT_PREFIX -------------------------------------
# lumilake CHECKS object-prefix on every submit but never REGISTERS it, so before
# this the gate had no key: every non-admin got "write on object-prefix/<p>
# denied" with no scope and no grants API to fix it.


async def test_object_prefix_claimed_by_first_writer(_ll_store) -> None:
    c = _Checker(_ll_store)
    log = _logging.getLogger("t")
    ref = _ResourceRef(kind=_RK.OBJECT_PREFIX.value, id="probe")
    # First writer is allowed AND becomes the owner.
    await c.require(_p("alice", "lumilake:jobs:write"), ref, _RA.WRITE.value, log)
    assert await _ll_store.get_level(_RK.OBJECT_PREFIX.value, "probe", "alice") is not None
    # Repeat writes by the owner keep working through the ordinary grant path.
    await c.require(_p("alice", "lumilake:jobs:write"), ref, _RA.WRITE.value, log)


async def test_object_prefix_claim_does_not_open_cross_tenant_writes(_ll_store) -> None:
    """The whole point: claiming must not become 'anyone can write anything'."""
    c = _Checker(_ll_store)
    log = _logging.getLogger("t")
    ref = _ResourceRef(kind=_RK.OBJECT_PREFIX.value, id="alice-space")
    await c.require(_p("alice", "lumilake:jobs:write"), ref, _RA.WRITE.value, log)
    with _pytest.raises(Exception):
        await c.require(_p("mallory", "lumilake:jobs:write"), ref, _RA.WRITE.value, log)


async def test_object_prefix_claim_is_atomic_under_concurrency(_ll_store) -> None:
    """Two simultaneous first-writers must not BOTH end up owning the prefix.

    A read-then-write would let both observe 'unowned'; the store does it in one
    INSERT ... WHERE NOT EXISTS, so exactly one wins.
    """
    import asyncio as _asyncio
    c = _Checker(_ll_store)
    log = _logging.getLogger("t")
    ref = _ResourceRef(kind=_RK.OBJECT_PREFIX.value, id="racy")
    results = await _asyncio.gather(
        c.require(_p("alice", "lumilake:jobs:write"), ref, _RA.WRITE.value, log),
        c.require(_p("bob", "lumilake:jobs:write"), ref, _RA.WRITE.value, log),
        return_exceptions=True,
    )
    ok = [r for r in results if not isinstance(r, Exception)]
    assert len(ok) == 1, f"exactly one claimer must win, got {len(ok)}"
    owners = [
        pid for pid in ("alice", "bob")
        if await _ll_store.get_level(_RK.OBJECT_PREFIX.value, "racy", pid) is not None
    ]
    assert len(owners) == 1, f"exactly one owner must exist, got {owners}"


async def test_table_is_not_claimable(_ll_store) -> None:
    """TABLE is pre-existing shared infrastructure — first touch must NOT own it."""
    c = _Checker(_ll_store)
    log = _logging.getLogger("t")
    ref = _ResourceRef(kind=_RK.TABLE.value, id="warehouse.public.events")
    with _pytest.raises(Exception):
        await c.require(_p("alice", "lumilake:jobs:write"), ref, _RA.WRITE.value, log)
