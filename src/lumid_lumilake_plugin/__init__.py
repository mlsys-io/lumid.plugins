"""Lumilake plugin: lum.id identity + jobs ACL + optional remote optimizer.

A single ``install()`` returns one ``BaseBindings``. The identity
provider, ACL store, ``PermissionChecker``, and ``ResourceRegistrar``
are installed on every load. The remote-optimizer surface
is opt-in: it activates when ``LUMILAKE_REMOTE_OPTIMIZER_URL`` is set.
"""

import asyncio
import logging
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
from .optimizer import OptimizerCatalogShapeError, RemoteOptimizerProvider
from .permissions import LumidPermissionChecker
from .registrar import LumidResourceRegistrar

logger = logging.getLogger(__name__)

# How hard install() tries to load the optimizer catalog before giving up on it
# FOR NOW. Giving up is not fatal: see _warm_optimizer_catalog.
_CATALOG_ATTEMPTS = 3
_CATALOG_BACKOFF_S = 2.0


async def _warm_optimizer_catalog(provider: RemoteOptimizerProvider) -> None:
    """Fetch the remote optimizer catalog, retrying briefly; never fatal.

    install() used to call list_optimizers() bare. One timeout from the
    optimizer service at boot raised out of install(), Lumilake skipped the
    WHOLE plugin, and with LUMILAKE_REQUIRE_IDENTITY_PROVIDER set every request
    answered 503 "No IdentityProvider plugins registered": home Lumilake served
    nothing for 25 h (2026-11-24 05:56Z to 11-25 07:19Z) while the pod stayed
    Ready. Identity and permissions do not depend on the optimizer, so the
    catalog is now warmed best-effort: on failure the provider is still
    registered and list_optimizers() fetches again on first use (a failed fetch
    is never cached).
    """
    for attempt in range(1, _CATALOG_ATTEMPTS + 1):
        try:
            provider.list_optimizers()
            return
        except RuntimeError as exc:
            # A wrong-shaped answer is a misconfigured URL: say so, don't retry.
            if (
                isinstance(exc, OptimizerCatalogShapeError)
                or attempt == _CATALOG_ATTEMPTS
            ):
                logger.warning(
                    "optimizer catalog unavailable after %d attempts (%s); "
                    "identity and permissions load anyway, the catalog is "
                    "fetched again on first use",
                    attempt,
                    exc,
                )
                return
            await asyncio.sleep(_CATALOG_BACKOFF_S * attempt)


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
        await _warm_optimizer_catalog(provider)
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
