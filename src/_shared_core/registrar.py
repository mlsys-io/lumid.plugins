"""Host-neutral resource registrar: populate the ACL on lifecycle events.

A host fires ``register(principal, ResourceRef(kind, id), logger)`` after each
resource is persisted and ``deregister`` after each hard-delete. The registrar
writes an owner ``WRITE`` grant on register and wipes every grant on the
resource on deregister, so the ``PermissionChecker`` can read the current set.

At startup the host runs a reconcile sweep — ``reconcile`` is called with the
live resources, delegating the touch/drop policy to the store's ``reconcile``
(which is host-specific). ``session_start`` is captured at plugin-load so grants
written between load and the sweep survive it.

Kind-level refs (``resource.id is None``) on register/deregister are no-ops with
a logged warning. Plugins subclass this to set ``name`` (used in log lines).
"""

import logging
from collections.abc import Collection
from datetime import datetime

from lumid_hooks import PrincipalContext, ResourceRef

from .acl import GrantLevel, GrantStore


class ResourceRegistrar:
    name = "lumid_plugin._core.registrar"

    def __init__(self, store: GrantStore, session_start: datetime) -> None:
        self._store = store
        self._session_start = session_start

    async def register(
        self,
        principal: PrincipalContext,
        resource: ResourceRef,
        logger: logging.Logger,
    ) -> None:
        if resource.id is None:
            logger.warning(
                "%s: ignoring kind-level register kind=%s actor=%s",
                self.name,
                resource.kind,
                principal.principal_id,
            )
            return
        await self._store.grant(
            resource.kind, resource.id, principal.principal_id, GrantLevel.WRITE
        )
        logger.debug(
            "%s: grant %s/%s -> %s",
            self.name,
            resource.kind,
            resource.id,
            principal.principal_id,
        )

    async def deregister(
        self,
        principal: PrincipalContext,
        resource: ResourceRef,
        logger: logging.Logger,
    ) -> None:
        if resource.id is None:
            return
        removed = await self._store.delete_resource(resource.kind, resource.id)
        logger.debug(
            "%s: deregister %s/%s removed=%d actor=%s",
            self.name,
            resource.kind,
            resource.id,
            removed,
            principal.principal_id,
        )

    async def reconcile(
        self,
        resources: Collection[ResourceRef],
        logger: logging.Logger,
    ) -> None:
        pairs = [(r.kind, r.id) for r in resources if r.id is not None]
        skipped = len(resources) - len(pairs)
        if skipped:
            logger.debug(
                "%s: reconcile skipping %d kind-level ref(s)",
                self.name,
                skipped,
            )
        touched, deleted = await self._store.reconcile(pairs, self._session_start)
        logger.info(
            "%s: reconcile requested=%d touched=%d deleted=%d",
            self.name,
            len(pairs),
            touched,
            deleted,
        )


__all__ = ["ResourceRegistrar"]
