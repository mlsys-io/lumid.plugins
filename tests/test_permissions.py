"""Tests for LumidPermissionChecker."""

import logging
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from fastapi import HTTPException
from flowmesh_hook import ResourceAction, ResourceKind
from lumid_hooks import PrincipalContext, ResourceRef

from lumid_flowmesh_plugin.acl import GrantLevel, GrantStore, open_store
from lumid_flowmesh_plugin.permissions import LumidPermissionChecker


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[GrantStore]:
    async with open_store(tmp_path / "acl.sqlite") as s:
        yield s


def _principal(pid: str, *scopes: str) -> PrincipalContext:
    return PrincipalContext(
        principal_id=pid,
        org_id="lumid",
        external_id=pid,
        principal_type="user",
        scopes=list(scopes),
    )


WF = ResourceKind.WORKFLOW.value
TASK = ResourceKind.TASK.value
NODE = ResourceKind.NODE.value
WORKER = ResourceKind.WORKER.value
SYSTEM = ResourceKind.SYSTEM.value
RESULT = ResourceKind.RESULT.value
WRITE = ResourceAction.WRITE.value
READ = ResourceAction.READ.value
CANCEL = ResourceAction.CANCEL.value
ADMIN = ResourceAction.ADMIN.value


@pytest.mark.parametrize("admin_scope", ["*", "flowmesh:*", "flowmesh:admin"])
async def test_admin_bypass_all_actions(
    store: GrantStore, logger: logging.Logger, admin_scope: str
) -> None:
    checker = LumidPermissionChecker(store)
    # Kind-level and concrete-id, both pass with no ACL row at all.
    await checker.require(_principal("alice", admin_scope), ResourceRef(kind=WF), WRITE, logger)
    await checker.require(
        _principal("alice", admin_scope),
        ResourceRef(kind=WF, id="wf-owned-by-someone-else"),
        READ,
        logger,
    )
    assert await checker.accessible_ids(_principal("alice", admin_scope), WF, READ, logger) is None


@pytest.mark.parametrize(
    "kind,action,scope",
    [
        (WF, READ, "flowmesh:workflows:read"),
        (WF, WRITE, "flowmesh:workflows:write"),
        (TASK, READ, "flowmesh:tasks:read"),
        (RESULT, READ, "flowmesh:results:read"),
        (RESULT, WRITE, "flowmesh:results:write"),
        (NODE, READ, "flowmesh:nodes:read"),
        (NODE, WRITE, "flowmesh:nodes:write"),
        (WORKER, READ, "flowmesh:workers:read"),
        (WORKER, WRITE, "flowmesh:workers:write"),
        (SYSTEM, READ, "flowmesh:system:read"),
    ],
)
async def test_kind_level_scope_grants_access(
    store: GrantStore, logger: logging.Logger, kind: str, action: str, scope: str
) -> None:
    checker = LumidPermissionChecker(store)
    await checker.require(_principal("alice", scope), ResourceRef(kind=kind), action, logger)


@pytest.mark.parametrize(
    "kind,action",
    [
        (WF, READ),
        (WF, WRITE),
        (TASK, READ),
        (RESULT, READ),
        (RESULT, WRITE),
        (NODE, READ),
        (NODE, WRITE),
        (WORKER, READ),
        (WORKER, WRITE),
        (SYSTEM, READ),
    ],
)
async def test_kind_level_denies_without_scope(
    store: GrantStore, logger: logging.Logger, kind: str, action: str
) -> None:
    checker = LumidPermissionChecker(store)
    with pytest.raises(HTTPException) as exc:
        await checker.require(_principal("alice"), ResourceRef(kind=kind), action, logger)
    assert exc.value.status_code == 403


async def test_kind_level_denies_with_wrong_scope(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    # Has nodes:write but tries to create a workflow.
    with pytest.raises(HTTPException) as exc:
        await checker.require(
            _principal("alice", "flowmesh:nodes:write"),
            ResourceRef(kind=WF),
            WRITE,
            logger,
        )
    assert exc.value.status_code == 403


async def test_concrete_id_grantee_allowed(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(WF, "wf-1", "alice", GrantLevel.WRITE)
    for action in (READ, WRITE, CANCEL):
        await checker.require(
            _principal("alice"), ResourceRef(kind=WF, id="wf-1"), action, logger
        )


async def test_concrete_id_second_grantee_allowed(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(WF, "wf-1", "alice", GrantLevel.WRITE)
    await store.grant(WF, "wf-1", "bob", GrantLevel.WRITE)
    await checker.require(
        _principal("bob"), ResourceRef(kind=WF, id="wf-1"), READ, logger
    )


async def test_concrete_id_non_grantee_denied(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(WF, "wf-1", "alice", GrantLevel.WRITE)
    with pytest.raises(HTTPException) as exc:
        await checker.require(_principal("bob"), ResourceRef(kind=WF, id="wf-1"), READ, logger)
    assert exc.value.status_code == 403


async def test_concrete_id_unknown_resource_denied(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    with pytest.raises(HTTPException) as exc:
        await checker.require(
            _principal("alice"), ResourceRef(kind=WF, id="never-registered"), READ, logger
        )
    assert exc.value.status_code == 403


async def test_concrete_id_non_grantee_with_read_scope_denied(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(WF, "wf-1", "alice", GrantLevel.WRITE)
    with pytest.raises(HTTPException) as exc:
        await checker.require(
            _principal("ops", "flowmesh:workflows:read"),
            ResourceRef(kind=WF, id="wf-1"),
            READ,
            logger,
        )
    assert exc.value.status_code == 403


async def test_concrete_id_read_grantee_cannot_mutate(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(WF, "wf-1", "alice", GrantLevel.READ)
    await checker.require(
        _principal("alice"), ResourceRef(kind=WF, id="wf-1"), READ, logger
    )
    for action in (WRITE, CANCEL):
        with pytest.raises(HTTPException) as exc:
            await checker.require(
                _principal("alice"), ResourceRef(kind=WF, id="wf-1"), action, logger
            )
        assert exc.value.status_code == 403


async def test_concrete_id_admin_action_denied_for_grantee(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(WF, "wf-1", "alice", GrantLevel.WRITE)  # WRITE-level owner
    with pytest.raises(HTTPException) as exc:
        await checker.require(
            _principal("alice"), ResourceRef(kind=WF, id="wf-1"), ADMIN, logger
        )
    assert exc.value.status_code == 403
    assert "admin-only" in exc.value.detail


async def test_result_ownership_resolves_against_task_grant(
    store: GrantStore, logger: logging.Logger
) -> None:
    # RESULT has no grants of its own; ownership is the owning task's grant
    # (result id == task id). FlowMesh never registers RESULT directly.
    checker = LumidPermissionChecker(store)
    await store.grant(TASK, "t-1", "alice", GrantLevel.WRITE)
    await checker.require(
        _principal("alice"), ResourceRef(kind=RESULT, id="t-1"), READ, logger
    )
    with pytest.raises(HTTPException):
        await checker.require(
            _principal("bob"), ResourceRef(kind=RESULT, id="t-1"), READ, logger
        )


async def test_kind_level_unsupported_pair_message(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    with pytest.raises(HTTPException) as exc:
        await checker.require(
            _principal("alice"), ResourceRef(kind="banana"), READ, logger
        )
    assert exc.value.status_code == 403
    assert "unsupported" in exc.value.detail


async def test_kind_level_admin_only_pair_message(
    store: GrantStore, logger: logging.Logger
) -> None:
    # SYSTEM/WRITE is a recognised pair with no kind-level scope -> admin-only.
    checker = LumidPermissionChecker(store)
    with pytest.raises(HTTPException) as exc:
        await checker.require(
            _principal("alice"), ResourceRef(kind=SYSTEM), WRITE, logger
        )
    assert exc.value.status_code == 403
    assert "admin-only" in exc.value.detail


async def test_accessible_ids_returns_granted_set(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(WF, "wf-1", "alice", GrantLevel.WRITE)
    await store.grant(WF, "wf-2", "alice", GrantLevel.WRITE)
    await store.grant(WF, "wf-3", "bob", GrantLevel.WRITE)
    assert await checker.accessible_ids(_principal("alice"), WF, READ, logger) == frozenset(
        {"wf-1", "wf-2"}
    )
    assert await checker.accessible_ids(_principal("bob"), WF, READ, logger) == frozenset(
        {"wf-3"}
    )


async def test_accessible_ids_includes_shared_resources(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(WF, "wf-1", "alice", GrantLevel.WRITE)
    await store.grant(WF, "wf-1", "bob", GrantLevel.WRITE)
    await store.grant(WF, "wf-2", "bob", GrantLevel.WRITE)
    assert await checker.accessible_ids(_principal("bob"), WF, READ, logger) == frozenset(
        {"wf-1", "wf-2"}
    )


async def test_accessible_ids_admin_returns_none(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    assert (
        await checker.accessible_ids(_principal("alice", "*"), WF, READ, logger) is None
    )


async def test_accessible_ids_with_read_scope_returns_granted(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(WF, "wf-1", "alice", GrantLevel.WRITE)
    await store.grant(WF, "wf-2", "bob", GrantLevel.WRITE)
    result = await checker.accessible_ids(
        _principal("alice", "flowmesh:workflows:read"), WF, READ, logger
    )
    assert result == frozenset({"wf-1"})


async def test_accessible_ids_write_action_excludes_read_grants(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(WF, "wf-write", "alice", GrantLevel.WRITE)
    await store.grant(WF, "wf-read", "alice", GrantLevel.READ)
    assert await checker.accessible_ids(_principal("alice"), WF, READ, logger) == frozenset(
        {"wf-write", "wf-read"}
    )
    assert await checker.accessible_ids(_principal("alice"), WF, WRITE, logger) == frozenset(
        {"wf-write"}
    )


async def test_accessible_ids_admin_action_returns_empty(
    store: GrantStore, logger: logging.Logger
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(WF, "wf-1", "alice", GrantLevel.WRITE)
    assert await checker.accessible_ids(_principal("alice"), WF, ADMIN, logger) == frozenset()


# --- Fleet kinds -------------------------------------------------------------
# Regression: office reported a healthy 12-worker fleet as an empty one for a
# full day. Workers register under the fleet's own credential, so their grants
# name that principal; filtering a human's list by ownership matched nothing
# and the API answered `200 []` with every layer below correct.


@pytest.mark.parametrize(
    ("kind", "scope"),
    [(WORKER, "flowmesh:workers:read"), (NODE, "flowmesh:nodes:read")],
)
async def test_fleet_kinds_unfiltered_with_kind_level_scope(
    store: GrantStore, kind: str, scope: str
) -> None:
    """The kind-level scope authorizes the whole fleet -- no ownership filter."""
    checker = LumidPermissionChecker(store)
    logger = logging.getLogger("t")
    # Grants exist, but under the fleet credential, not this caller.
    await store.grant(kind, "wkr-28", "admin", GrantLevel.WRITE)
    assert await checker.accessible_ids(_principal("alice", scope), kind, READ, logger) is None


@pytest.mark.parametrize("kind", [WORKER, NODE])
async def test_fleet_kinds_denied_without_scope(store: GrantStore, kind: str) -> None:
    """No kind-level scope and no grant means no rows -- this is not a public read."""
    checker = LumidPermissionChecker(store)
    logger = logging.getLogger("t")
    await store.grant(kind, "wkr-28", "admin", GrantLevel.WRITE)
    assert await checker.accessible_ids(_principal("alice"), kind, READ, logger) == frozenset()


@pytest.mark.parametrize("kind", [WORKER, NODE])
async def test_fleet_kinds_without_scope_list_own_grants(store: GrantStore, kind: str) -> None:
    """Without the scope a principal lists exactly what it may read by id: its grants."""
    checker = LumidPermissionChecker(store)
    logger = logging.getLogger("t")
    await store.grant(kind, "fleet-1", "fleet", GrantLevel.WRITE)
    await store.grant(kind, "mine", "alice", GrantLevel.WRITE)
    got = await checker.accessible_ids(_principal("alice"), kind, READ, logger)
    assert got == frozenset({"mine"})


@pytest.mark.parametrize(
    ("kind", "scope"),
    [(WF, "flowmesh:workflows:read"), (TASK, "flowmesh:tasks:read")],
)
async def test_per_principal_kinds_still_ownership_filtered(
    store: GrantStore, kind: str, scope: str
) -> None:
    """The tenancy boundary: holding the kind-level scope must NOT reveal
    another principal's rows. Guards against opting these into fleet_kinds."""
    checker = LumidPermissionChecker(store)
    logger = logging.getLogger("t")
    await store.grant(kind, "owned-by-alice", "alice", GrantLevel.READ)
    await store.grant(kind, "owned-by-bob", "bob", GrantLevel.READ)
    got = await checker.accessible_ids(_principal("alice", scope), kind, READ, logger)
    assert got == frozenset({"owned-by-alice"}), "scope must not widen to bob's rows"


# Regression (mlsys-io/FlowMesh#148): a principal holding `flowmesh:workers:read`
# listed every worker with its full record, yet `GET /workers/{id}` for one of
# those same workers answered 403 -- the list honoured the fleet scope and the
# concrete-id check still demanded a grant nobody but the fleet credential holds.

_FLEET_SCOPES = {
    WORKER: ("flowmesh:workers:read", "flowmesh:workers:write"),
    NODE: ("flowmesh:nodes:read", "flowmesh:nodes:write"),
}


@pytest.mark.parametrize("kind", [WORKER, NODE])
async def test_fleet_kinds_concrete_read_with_kind_level_scope(
    store: GrantStore, logger: logging.Logger, kind: str
) -> None:
    """The read scope that lists the fleet also reads any member by id."""
    checker = LumidPermissionChecker(store)
    read_scope, _ = _FLEET_SCOPES[kind]
    await store.grant(kind, "fleet-1", "fleet", GrantLevel.WRITE)
    await checker.require(
        _principal("alice", read_scope), ResourceRef(kind=kind, id="fleet-1"), READ, logger
    )


@pytest.mark.parametrize("kind", [WORKER, NODE])
async def test_fleet_kinds_concrete_read_denied_without_scope(
    store: GrantStore, logger: logging.Logger, kind: str
) -> None:
    checker = LumidPermissionChecker(store)
    await store.grant(kind, "fleet-1", "fleet", GrantLevel.WRITE)
    with pytest.raises(HTTPException) as exc:
        await checker.require(
            _principal("alice"), ResourceRef(kind=kind, id="fleet-1"), READ, logger
        )
    assert exc.value.status_code == 403


@pytest.mark.parametrize("kind", [WORKER, NODE])
@pytest.mark.parametrize("action", [WRITE, CANCEL])
async def test_fleet_kinds_concrete_mutation_still_needs_grant(
    store: GrantStore, logger: logging.Logger, kind: str, action: str
) -> None:
    """A kind-level write scope must not open mutation of every worker or node."""
    checker = LumidPermissionChecker(store)
    read_scope, write_scope = _FLEET_SCOPES[kind]
    await store.grant(kind, "fleet-1", "fleet", GrantLevel.WRITE)
    await store.grant(kind, "mine", "alice", GrantLevel.WRITE)
    alice = _principal("alice", read_scope, write_scope)
    with pytest.raises(HTTPException) as exc:
        await checker.require(alice, ResourceRef(kind=kind, id="fleet-1"), action, logger)
    assert exc.value.status_code == 403
    await checker.require(alice, ResourceRef(kind=kind, id="mine"), action, logger)


@pytest.mark.parametrize("kind", [WORKER, NODE])
@pytest.mark.parametrize("action", [READ, WRITE, CANCEL, ADMIN])
@pytest.mark.parametrize("holds_scope", [True, False])
@pytest.mark.parametrize("grant_level", [None, GrantLevel.READ, GrantLevel.WRITE])
async def test_fleet_kinds_require_agrees_with_accessible_ids(
    store: GrantStore,
    logger: logging.Logger,
    kind: str,
    action: str,
    holds_scope: bool,
    grant_level: GrantLevel | None,
) -> None:
    """`require` on an id passes exactly when `accessible_ids` covers that id."""
    checker = LumidPermissionChecker(store)
    read_scope, write_scope = _FLEET_SCOPES[kind]
    scopes = [read_scope if action == READ else write_scope] if holds_scope else []
    alice = _principal("alice", *scopes)
    await store.grant(kind, "granted", "fleet", GrantLevel.WRITE)
    await store.grant(kind, "ungranted", "fleet", GrantLevel.WRITE)
    if grant_level is not None:
        await store.grant(kind, "granted", "alice", grant_level)

    allowed = await checker.accessible_ids(alice, kind, action, logger)
    for rid in ("granted", "ungranted"):
        try:
            await checker.require(alice, ResourceRef(kind=kind, id=rid), action, logger)
            passed = True
        except HTTPException:
            passed = False
        assert passed == (allowed is None or rid in allowed), (rid, allowed)


@pytest.mark.parametrize(
    ("kind", "scope"),
    [(WF, "flowmesh:workflows:read"), (TASK, "flowmesh:tasks:read")],
)
async def test_per_principal_kinds_concrete_read_still_needs_grant(
    store: GrantStore, logger: logging.Logger, kind: str, scope: str
) -> None:
    """The fleet exception must not leak to per-principal kinds."""
    checker = LumidPermissionChecker(store)
    await store.grant(kind, "owned-by-bob", "bob", GrantLevel.WRITE)
    with pytest.raises(HTTPException) as exc:
        await checker.require(
            _principal("alice", scope), ResourceRef(kind=kind, id="owned-by-bob"), READ, logger
        )
    assert exc.value.status_code == 403
