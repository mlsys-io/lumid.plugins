"""LumidResourceRegistrar — populate the ACL on Lumilake resource lifecycle events."""

import logging
from collections.abc import Collection
from datetime import datetime

from lumid_hooks import PrincipalContext, ResourceRef

from .acl import GrantLevel, GrantStore


class LumidResourceRegistrar:
    name = "lumid_lumilake_plugin.registrar"

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
