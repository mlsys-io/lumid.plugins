from typing import Any

import httpx
from lumilake_server.runtime.optimizer.base import BaseOptimizer
from lumilake_server.runtime.optimizer.remote import RemoteOptimizer


class RemoteOptimizerProvider:
    """OptimizerProvider that lists + instantiates remote-hosted optimizers.

    One-shot list at install; no retry, no TTL.
    """

    def __init__(self, base_url: str, bearer: str | None = None) -> None:
        self._base_url = base_url
        self._bearer = bearer
        self._types: list[str] | None = None

    def list_optimizers(self) -> list[str]:
        if self._types is None:
            self._types = self._fetch_remote_types()
        return list(self._types)

    def create_optimizer(self, optimizer_type: str, **kwargs: Any) -> BaseOptimizer:
        if optimizer_type not in self.list_optimizers():
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
        if self._bearer:
            headers["Authorization"] = f"Bearer {self._bearer}"
        try:
            resp = httpx.get(url, headers=headers, timeout=10.0)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"failed to fetch optimizer list from {url}: {exc}"
            ) from exc
        data = resp.json()
        types = data.get("types")
        if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
            raise RuntimeError(
                f"unexpected response shape from {url}: "
                f"expected {{'types': [str]}}, got {data!r}"
            )
        return types


__all__ = ["RemoteOptimizerProvider"]
