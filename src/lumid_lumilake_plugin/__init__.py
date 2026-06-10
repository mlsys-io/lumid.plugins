"""Lumilake plugin: lum.id identity + optional jobs ACL + optional remote optimizer.

A single ``install()`` returns one ``BaseBindings``. Identity, ACL, and
remote-optimizer surfaces each activate only when their env vars are
set, so deployments can opt into any subset (e.g. remote-optimizer
only, no identity).
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from lumid_hooks import IdentityProvider
from lumilake_hook import BaseBindings, OptimizerProvider

from ._core import (
    IntrospectedToken,
    LumidIdentityProvider,
    build_email_cache,
)
from .acl import open_store
from .config import Settings
from .optimizer import RemoteOptimizerProvider
from .permissions import LumidPermissionChecker
from .registrar import LumidResourceRegistrar


@asynccontextmanager
async def install() -> AsyncIterator[BaseBindings]:
    settings = Settings.from_env()
    email_cache = build_email_cache()

    identity_providers: tuple[IdentityProvider, ...] = ()
    if settings.lum_id_base_url:
        identity_providers = (
            LumidIdentityProvider(
                base_url=settings.lum_id_base_url,
                org_id=settings.lumid_org_id,
                email_cache=email_cache,
                name="lumid_lumilake_plugin.identity",
            ),
        )

    optimizer_providers: tuple[OptimizerProvider, ...] = ()
    if settings.lumilake_remote_optimizer_url:
        provider = RemoteOptimizerProvider(
            base_url=settings.lumilake_remote_optimizer_url
        )
        provider.list_optimizers()
        optimizer_providers = (provider,)

    async with open_store(settings.lumid_acl_db_path) as store:
        session_start = datetime.now(UTC)
        yield BaseBindings(
            identity_providers=identity_providers,
            permission_checkers=(LumidPermissionChecker(store),),
            resource_registrars=(LumidResourceRegistrar(store, session_start),),
            optimizer_providers=optimizer_providers,
        )


__all__ = [
    "BaseBindings",
    "IntrospectedToken",
    "LumidIdentityProvider",
    "LumidPermissionChecker",
    "LumidResourceRegistrar",
    "install",
]
