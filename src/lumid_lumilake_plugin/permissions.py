"""Lumilake authorization policy for the shared ``PermissionChecker`` engine.

Defines the Lumilake scope vocabulary; the decision logic lives in
``_core.permissions``. ``flowmesh:admin`` is included in the admin-scope set so
shared platform admins retain access without needing a Lumilake-specific scope.

Kind-level checks are gated on ``lumilake:jobs:{read,write,cancel}`` and
``lumilake:workers:read``; concrete-id checks require a grant whose level covers
the action (READ needs READ, WRITE and CANCEL need WRITE). The ``admin`` action is
never grant-satisfiable. Lumilake has no cross-kind ownership indirection, so the
ownership map is empty.

WORKER is a **fleet kind**: it describes the shared FlowMesh fleet that no
Lumilake principal owns, so ``lumilake:workers:read`` alone authorizes reading
workers, listed or by id; other actions stay grant-only. Lumilake's
``ResourceKind`` has no NODE, so WORKER is the only one. Every other kind here
is per-principal and must stay out of ``fleet_kinds`` -- their ownership filter
is the tenancy boundary.
"""

from lumilake_hook import ResourceAction, ResourceKind

from ._core import GrantLevel, GrantStore, PermissionChecker, PermissionPolicy

_POLICY = PermissionPolicy(
    admin_scopes=frozenset({"*", "lumilake:*", "lumilake:admin", "flowmesh:admin"}),
    # Anything not in this map is admin-only at kind level.
    kind_level_scopes={
        (ResourceKind.JOB.value, ResourceAction.READ.value): "lumilake:jobs:read",
        (ResourceKind.JOB.value, ResourceAction.WRITE.value): "lumilake:jobs:write",
        (ResourceKind.JOB.value, ResourceAction.CANCEL.value): "lumilake:jobs:cancel",
        # routes/workers.py enumerates the FLOWMESH fleet through Lumilake. Without
        # this entry the kind-level check falls through to "admin-only" and every
        # non-admin gets a flat 403 on /workers.
        (ResourceKind.WORKER.value, ResourceAction.READ.value): "lumilake:workers:read",
    },
    # Grant level a concrete-id action needs. Actions absent here (e.g. ``admin``)
    # are never satisfiable by a grant — only the admin-scope bypass clears them.
    required_level={
        ResourceAction.READ.value: GrantLevel.READ,
        ResourceAction.WRITE.value: GrantLevel.WRITE,
        ResourceAction.CANCEL.value: GrantLevel.WRITE,
    },
    ownership_kind={},
    # Workers are shared FlowMesh fleet infrastructure that no Lumilake principal
    # owns -- they are registered by the fleet's own credential, so their grants
    # never name a human and an ownership filter returns zero rows for every real
    # user. Adding the scope above WITHOUT this would swap the 403 for a silently
    # empty list, which is worse. JOB/ARTIFACT/TRACE/TABLE/OBJECT_PREFIX stay out:
    # they are per-principal and their filter IS the tenancy boundary.
    fleet_kinds=frozenset({ResourceKind.WORKER.value}),
    fleet_actions=frozenset({ResourceAction.READ.value}),
    # OBJECT_PREFIX is CHECKED on every job submit (routes/jobs.py
    # _require_location_permission) but NEVER REGISTERED -- lumilake registers JOB,
    # TRACE and ARTIFACT and nothing else. So the gate had no key: every non-admin
    # got "write on object-prefix/<p> denied" with no scope, no grants API and no
    # self-service path to satisfy it. Measured 2026-09-14 with a real role=user.
    #
    # Claim-on-first-use: the first principal to write an UNOWNED prefix becomes its
    # owner, and every other principal is then denied by the ordinary grant check --
    # so this opens self-service WITHOUT opening cross-tenant writes. The trade is
    # name squatting: whoever submits first owns that prefix string. Accepted
    # deliberately (operator decision 2026-09-14); the alternative was an
    # admin-only job surface.
    #
    # TABLE is NOT claimable: a DB table is pre-existing shared infrastructure, so
    # first-touch ownership there would hand a caller something they did not create.
    claimable_kinds=frozenset({ResourceKind.OBJECT_PREFIX.value}),
    valid_kinds=frozenset(k.value for k in ResourceKind),
    valid_actions=frozenset(a.value for a in ResourceAction),
)


class LumidPermissionChecker(PermissionChecker):
    name = "lumid_lumilake_plugin.permissions"

    def __init__(self, store: GrantStore) -> None:
        super().__init__(store, _POLICY)
