"""Lumilake authorization policy for the shared ``PermissionChecker`` engine.

Defines the Lumilake scope vocabulary; the decision logic lives in
``_core.permissions``. ``flowmesh:admin`` is included in the admin-scope set so
shared platform admins retain access without needing a Lumilake-specific scope.

Kind-level checks are gated on ``lumilake:jobs:{read,write,cancel}``; concrete-id
checks require a grant whose level covers the action (READ needs READ, WRITE and
CANCEL need WRITE). The ``admin`` action is never grant-satisfiable. Lumilake has
no cross-kind ownership indirection, so the ownership map is empty.
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
    },
    # Grant level a concrete-id action needs. Actions absent here (e.g. ``admin``)
    # are never satisfiable by a grant — only the admin-scope bypass clears them.
    required_level={
        ResourceAction.READ.value: GrantLevel.READ,
        ResourceAction.WRITE.value: GrantLevel.WRITE,
        ResourceAction.CANCEL.value: GrantLevel.WRITE,
    },
    ownership_kind={},
    valid_kinds=frozenset(k.value for k in ResourceKind),
    valid_actions=frozenset(a.value for a in ResourceAction),
)


class LumidPermissionChecker(PermissionChecker):
    name = "lumid_lumilake_plugin.permissions"

    def __init__(self, store: GrantStore) -> None:
        super().__init__(store, _POLICY)
