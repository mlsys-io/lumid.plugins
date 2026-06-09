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
    """Regression test: pre-existing but read-only DB must not cause fail-open.

    Before the BEGIN IMMEDIATE fix, a plain BEGIN; ROLLBACK succeeded on a
    read-only file because SQLite defers write-lock acquisition to the first
    real write statement.  BEGIN IMMEDIATE acquires a RESERVED lock immediately,
    so this case is caught at install time rather than at the first grant write.

    sqlite3.Connection is a C extension type whose instance attributes are
    read-only slots — instance-level method replacement is not possible.
    We instead use sqlite3.connect()'s ``factory`` parameter to pass in a
    subclass that overrides execute() to raise OperationalError on
    "BEGIN IMMEDIATE", giving a fully deterministic simulation of a read-only
    database regardless of filesystem or user permissions.

    The patch targets lumid_lumilake_plugin.acl._connect so only the
    second call (from install()) gets the failing factory; the first call (from
    open_store_sync() in test setup) must succeed to bootstrap the schema.
    """
    import lumid_lumilake_plugin.acl as acl_module

    class _ReadOnlyConn(sqlite3.Connection):
        """sqlite3.Connection subclass that rejects BEGIN IMMEDIATE.

        The positional-only `parameters: object` signature matches the arity
        of the real sqlite3.Connection.execute stub while accepting any value.
        The # type: ignore[arg-type] on the super() call is needed because
        `object` is wider than SupportsLenAndGetItem | Mapping; at runtime
        sqlite3 accepts () as the default without complaint.
        """

        def execute(
            self,
            sql: str,
            parameters: object = (),
            /,
        ) -> sqlite3.Cursor:
            if sql.strip().upper() == "BEGIN IMMEDIATE":
                raise sqlite3.OperationalError("attempt to write a readonly database")
            # parameters is typed as `object` (wider than the stub's
            # SupportsLenAndGetItem | Mapping) so we need to suppress here;
            # at runtime sqlite3 accepts () as the default fine.
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
        from pathlib import Path as _Path

        _Path(path).parent.mkdir(parents=True, exist_ok=True)  # type: ignore[arg-type]
        conn = sqlite3.connect(
            str(path),
            check_same_thread=False,
            isolation_level=None,
            factory=_ReadOnlyConn,
        )
        conn.executescript(acl_module._SCHEMA)
        return conn

    monkeypatch.setattr(acl_module, "_connect", _patched_connect)

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
    (install + future direct callers) benefits without duplicating the BEGIN
    IMMEDIATE dance."""
    import lumid_lumilake_plugin.acl as acl_module

    class _ReadOnlyConn(sqlite3.Connection):
        def execute(
            self,
            sql: str,
            parameters: object = (),
            /,
        ) -> sqlite3.Cursor:
            if sql.strip().upper() == "BEGIN IMMEDIATE":
                raise sqlite3.OperationalError("attempt to write a readonly database")
            return super().execute(sql, parameters)  # type: ignore[arg-type]

    db_path = tmp_path / "ro_acl.sqlite"
    # Bootstrap schema with the real _connect first.
    open_store_sync(db_path)

    def _patched_connect(path: object) -> sqlite3.Connection:
        from pathlib import Path as _Path

        _Path(path).parent.mkdir(parents=True, exist_ok=True)  # type: ignore[arg-type]
        conn = sqlite3.connect(
            str(path),
            check_same_thread=False,
            isolation_level=None,
            factory=_ReadOnlyConn,
        )
        conn.executescript(acl_module._SCHEMA)
        return conn

    monkeypatch.setattr(acl_module, "_connect", _patched_connect)

    with pytest.raises(RuntimeError, match="LUMID_ACL_DB_PATH"):
        async with open_store(db_path):
            pass
