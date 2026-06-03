"""LumidPermissionChecker — admin bypass + scope vocabulary + ACL-store grants.

``flowmesh:admin`` is included in the admin-scope set so shared platform
admins retain access without needing a Lumilake-specific scope.
"""

import logging

from fastapi import HTTPException, status
from lumid_hooks import PrincipalContext, ResourceRef
from lumilake_hook import ResourceAction, ResourceKind

from .acl import GrantLevel, GrantStore

_ADMIN_SCOPES: frozenset[str] = frozenset(
    {"*", "lumilake:*", "lumilake:admin", "flowmesh:admin"}
)

# Anything not in this map is admin-only at kind level.
_KIND_LEVEL_SCOPES: dict[tuple[str, str], str] = {
    (ResourceKind.JOB.value, ResourceAction.READ.value): "lumilake:jobs:read",
    (ResourceKind.JOB.value, ResourceAction.WRITE.value): "lumilake:jobs:write",
    (ResourceKind.JOB.value, ResourceAction.CANCEL.value): "lumilake:jobs:cancel",
}

# Grant level a concrete-id action needs. Actions absent here (e.g. ``admin``)
# are never satisfiable by a grant — only the admin-scope bypass clears them.
_REQUIRED_LEVEL: dict[str, GrantLevel] = {
    ResourceAction.READ.value: GrantLevel.READ,
    ResourceAction.WRITE.value: GrantLevel.WRITE,
    ResourceAction.CANCEL.value: GrantLevel.WRITE,
}

_VALID_KINDS: frozenset[str] = frozenset(k.value for k in ResourceKind)
_VALID_ACTIONS: frozenset[str] = frozenset(a.value for a in ResourceAction)


def _is_admin(principal: PrincipalContext) -> bool:
    return any(scope in _ADMIN_SCOPES for scope in principal.scopes)


def _recognised(kind: str, action: str) -> bool:
    return kind in _VALID_KINDS and action in _VALID_ACTIONS


class LumidPermissionChecker:
    name = "lumid_lumilake_plugin.permissions"

    def __init__(self, store: GrantStore) -> None:
        self._store = store

    async def require(
        self,
        principal: PrincipalContext,
        resource: ResourceRef,
        action: str,
        logger: logging.Logger,
    ) -> None:
        if _is_admin(principal):
            return

        if resource.id is None:
            required_scope = _KIND_LEVEL_SCOPES.get((resource.kind, action))
            if required_scope is not None:
                if required_scope in principal.scopes:
                    return
                detail = f"kind-level {action} on {resource.kind} requires {required_scope!r}"
            elif _recognised(resource.kind, action):
                detail = f"kind-level {action} on {resource.kind} is admin-only"
            else:
                detail = f"unsupported kind-level {action} on {resource.kind}"
            raise self._deny(logger, detail)

        if not _recognised(resource.kind, action):
            raise self._deny(
                logger, f"unsupported {action} on {resource.kind}/{resource.id}"
            )

        required_level = _REQUIRED_LEVEL.get(action)
        if required_level is None:
            raise self._deny(
                logger, f"{action} on {resource.kind}/{resource.id} is admin-only"
            )

        level = await self._store.get_level(resource.kind, resource.id, principal.principal_id)
        if level is not None and level >= required_level:
            return
        raise self._deny(
            logger,
            f"{action} on {resource.kind}/{resource.id} denied for "
            f"principal {principal.principal_id}",
        )

    async def accessible_ids(
        self,
        principal: PrincipalContext,
        kind: str,
        action: str,
        logger: logging.Logger,
    ) -> frozenset[str] | None:
        if _is_admin(principal):
            return None
        required_level = _REQUIRED_LEVEL.get(action)
        if required_level is None:
            return frozenset()
        return await self._store.list_ids_for_principal(
            principal.principal_id, kind, required_level
        )

    def _deny(self, logger: logging.Logger, detail: str) -> HTTPException:
        logger.warning("%s: %s", self.name, detail)
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
