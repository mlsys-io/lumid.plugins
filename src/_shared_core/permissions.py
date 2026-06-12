"""Host-neutral permission engine: admin bypass + scope vocabulary + ACL grants.

The authorization *algorithm* is shared; the *policy* (which scopes are admin,
which (kind, action) pairs map to which scope, what grant level each action
needs, and which kinds inherit ownership from another kind) is host-specific and
injected via ``PermissionPolicy``. This keeps the engine free of any host hook
import, so it stays in ``_shared_core`` (enforced by
``tests/test_shared_core.py``).

Policy resolution, in order:

* **Admin** — any scope in ``policy.admin_scopes`` bypasses every check.
* **Kind-level checks** (``resource.id is None``) require the scope mapped by
  ``policy.kind_level_scopes[(kind, action)]``. A recognised (kind, action)
  with no mapping is admin-only; an unrecognised one is unsupported. Both deny.
* **Concrete-id checks** require a grant whose level covers the action
  (``policy.required_level``). An action absent from that map is never
  grant-satisfiable. Kinds in ``policy.ownership_kind`` resolve their grant
  against the owning kind of the same id.
* **accessible_ids** returns the ids the principal can act on at the requested
  action's level, or ``None`` for admins.
"""

import logging
from dataclasses import dataclass

from fastapi import HTTPException, status
from lumid_hooks import PrincipalContext, ResourceRef

from .acl import GrantLevel, GrantStore


@dataclass(frozen=True)
class PermissionPolicy:
    """Host-specific authorization vocabulary consumed by ``PermissionChecker``."""

    admin_scopes: frozenset[str]
    kind_level_scopes: dict[tuple[str, str], str]
    required_level: dict[str, GrantLevel]
    ownership_kind: dict[str, str]
    valid_kinds: frozenset[str]
    valid_actions: frozenset[str]


class PermissionChecker:
    """ACL-backed authorization engine driven by an injected ``PermissionPolicy``.

    Plugins subclass this to set ``name`` (used in deny logs) and pass their
    policy.
    """

    name = "lumid_plugin._core.permissions"

    def __init__(self, store: GrantStore, policy: PermissionPolicy) -> None:
        self._store = store
        self._policy = policy

    def _is_admin(self, principal: PrincipalContext) -> bool:
        return any(scope in self._policy.admin_scopes for scope in principal.scopes)

    def _recognised(self, kind: str, action: str) -> bool:
        return kind in self._policy.valid_kinds and action in self._policy.valid_actions

    async def require(
        self,
        principal: PrincipalContext,
        resource: ResourceRef,
        action: str,
        logger: logging.Logger,
    ) -> None:
        if self._is_admin(principal):
            return

        policy = self._policy

        if resource.id is None:
            required_scope = policy.kind_level_scopes.get((resource.kind, action))
            if required_scope is not None:
                if required_scope in principal.scopes:
                    return
                detail = f"kind-level {action} on {resource.kind} requires {required_scope!r}"
            elif self._recognised(resource.kind, action):
                detail = f"kind-level {action} on {resource.kind} is admin-only"
            else:
                detail = f"unsupported kind-level {action} on {resource.kind}"
            raise self._deny(logger, detail)

        if not self._recognised(resource.kind, action):
            raise self._deny(
                logger, f"unsupported {action} on {resource.kind}/{resource.id}"
            )

        required_level = policy.required_level.get(action)
        if required_level is None:
            raise self._deny(
                logger, f"{action} on {resource.kind}/{resource.id} is admin-only"
            )

        owner_kind = policy.ownership_kind.get(resource.kind, resource.kind)
        level = await self._store.get_level(
            owner_kind, resource.id, principal.principal_id
        )
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
        if self._is_admin(principal):
            return None
        policy = self._policy
        required_level = policy.required_level.get(action)
        if required_level is None:
            # No grants can satisfy this action, so non-admins have no access.
            return frozenset()
        owner_kind = policy.ownership_kind.get(kind, kind)
        return await self._store.list_ids_for_principal(
            principal.principal_id, owner_kind, required_level
        )

    def _deny(self, logger: logging.Logger, detail: str) -> HTTPException:
        logger.warning("%s: %s", self.name, detail)
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


__all__ = [
    "PermissionChecker",
    "PermissionPolicy",
]
