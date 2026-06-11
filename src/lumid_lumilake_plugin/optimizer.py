"""``OptimizerProvider`` that proxies to a remote optimizer service."""

import os
from typing import Any
from urllib.parse import urlparse

import httpx
from lumilake_hook import OptimizerHandle, RemoteOptimizer

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})


def _validate_remote_url(base_url: str) -> None:
    """Reject anything other than ``https://`` or loopback ``http://``.

    Fails fast at install time before the catalog probe runs.
    """
    parsed = urlparse(base_url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and parsed.hostname in _LOOPBACK_HOSTS:
        return
    raise ValueError(
        "LUMILAKE_REMOTE_OPTIMIZER_URL must use https:// "
        "(or http:// for loopback only). "
        f"Got: {parsed.scheme}://{parsed.hostname}"
    )


class RemoteOptimizerProvider:
    """Lists + instantiates remote-hosted optimizers.

    Catalog is fetched once at install time using ``LUMILAKE_RUNTIME_TOKEN``;
    per-job schedule calls forward the submitter's bearer via
    ``runtime_token_var``.
    """

    def __init__(self, base_url: str) -> None:
        _validate_remote_url(base_url)
        self._base_url = base_url
        self._types: list[str] | None = None

    def list_optimizers(self) -> list[str]:
        if self._types is None:
            self._types = self._fetch_remote_types()
        return list(self._types)

    def create_optimizer(self, optimizer_type: str, **kwargs: Any) -> OptimizerHandle:
        # OptimizerProvider contract: compare case-insensitively, forward
        # the caller's original casing through to the remote.
        lowered = optimizer_type.lower()
        known = {t.lower() for t in self.list_optimizers()}
        if lowered not in known:
            raise ValueError(
                f"optimizer_type '{optimizer_type}' is not advertised by "
                f"remote {self._base_url}. Available: {self.list_optimizers()}"
            )
        return RemoteOptimizer(
            base_url=self._base_url, optimizer_type=optimizer_type, **kwargs
        )

    def _fetch_remote_types(self) -> list[str]:
        url = f"{self._base_url.rstrip('/')}/api/v1/optimizer"
        headers: dict[str, str] = {}
        runtime_token = os.getenv("LUMILAKE_RUNTIME_TOKEN", "")
        if runtime_token:
            headers["Authorization"] = f"Bearer {runtime_token}"
        try:
            resp = httpx.get(url, headers=headers, timeout=10.0)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"failed to fetch optimizer list from {url}: {exc}"
            ) from exc
        data = resp.json()
        if isinstance(data, dict):
            types = data.get("types")
            if isinstance(types, list) and all(isinstance(t, str) for t in types):
                return types
        raise RuntimeError(
            f"unexpected response shape from {url}: "
            f"expected {{'types': [str]}}, got {data!r}"
        )


__all__ = ["RemoteOptimizerProvider"]
