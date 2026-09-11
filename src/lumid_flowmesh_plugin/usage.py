"""RunmeshUsageSink — mirror lumid-tenant usage rows to Runmesh billing."""

import logging
from collections.abc import Sequence

import httpx
from flowmesh_hook import UsageRow

from ._core import TTLCache


class RunmeshUsageSink:
    """UsageSink[UsageRow] that POSTs rows to Runmesh's billing receiver.

    With this plugin as the sole IdentityProvider, every authenticated
    principal — and therefore every UsageRow that reaches us — was minted by
    our lum.id resolve path. We forward every row.

    `userEmail` is hydrated from the IdentityProvider's principal_id→email
    cache; rows whose principal isn't in the cache are skipped (they predate
    the current process or were resolved without an email claim — Runmesh
    can't bill them without a known account).

    Failures are logged and dropped; the host's deduplication elsewhere is
    the safety net against duplicates.
    """

    name = "lumid_flowmesh_plugin.usage"

    def __init__(
        self,
        *,
        base_url: str,
        secret: str,
        email_cache: TTLCache[str],
        timeout_sec: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._secret = secret
        self._email_cache = email_cache
        self._timeout_sec = timeout_sec

    async def emit(self, rows: Sequence[UsageRow], logger: logging.Logger) -> None:
        if not self._base_url or not self._secret or not rows:
            return

        async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
            for row in rows:
                principal_id = row["principal_id"]
                email = self._email_cache.get(principal_id)
                if email is None:
                    logger.warning(
                        "%s: skip task %s, no cached email for principal %s",
                        self.name,
                        row["task_id"],
                        principal_id,
                    )
                    continue
                await self._post_row(client, row, email, logger)

    async def _post_row(
        self,
        client: httpx.AsyncClient,
        row: UsageRow,
        email: str,
        logger: logging.Logger,
    ) -> None:
        body = {
            "userEmail": email,
            "userSub": row["principal_id"],
            "taskId": row["task_id"],
            "workflowId": None,
            "cost": str(row["cost"]),
            "durationSec": int(row["runtime_sec"]),
            "costPerHour": row["cost_per_hour"],
            "taskStatus": row["task_status"],
        }
        try:
            resp = await client.post(
                f"{self._base_url}/billing/flowmesh-entry",
                json=body,
                headers={"X-Bridge-Secret": self._secret},
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "%s: POST failed for task %s: %s",
                self.name,
                row["task_id"],
                exc,
            )
            return

        if resp.status_code != 200:
            logger.warning(
                "%s: Runmesh returned %d for task %s: %s",
                self.name,
                resp.status_code,
                row["task_id"],
                resp.text[:200],
            )
            return

        # Runmesh answers HTTP 200 and puts the real outcome in the body's
        # `code` (it is a RuoYi-style `R<T>` envelope). Checking only the status
        # therefore treats every application-level rejection as a success: the
        # entry is dropped, nothing is logged, and the ledger silently stops
        # growing.
        #
        # That is not hypothetical. Measured 2026-09-11 against the live bridge:
        #   HTTP 200 {"code":500,"msg":"unknown user"}
        # for any task whose owner has no matching `sys_user` row -- which is
        # every service-account-owned task -- while a provisioned user returned
        # {"code":200,...,"data":{"idempotent":false,...}}. Both looked
        # identical to this sink. Billing appeared to be running and was
        # discarding entries.
        try:
            payload = resp.json()
        except ValueError:
            payload = None
        code = payload.get("code") if isinstance(payload, dict) else None
        if code is not None and int(code) != 200:
            logger.warning(
                "%s: Runmesh rejected task %s: code=%s msg=%s",
                self.name,
                row["task_id"],
                code,
                (payload or {}).get("msg"),
            )
