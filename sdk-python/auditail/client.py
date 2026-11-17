"""
Auditail Python SDK — Client
"""

import asyncio
import atexit
import concurrent.futures
import inspect
import json
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional

from .types import AuditEvent, GuardApproval, GuardOptions, GuardResult, GuardrailRule

SDK_VERSION = "0.12.0"
MAX_QUEUE = 10_000
MAX_BATCH = 50
MAX_DELIVERY_ATTEMPTS = 5
DEFAULT_REDACT = {
    "password", "passwd", "secret", "token", "apikey", "api_key", "authorization", "auth",
    "ssn", "creditcard", "credit_card", "cardnumber", "card_number", "cvv", "privatekey", "private_key",
}


def _redact(value: Any, keys: set, depth: int = 0) -> Any:
    if depth > 10:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if str(k).lower() in keys else _redact(v, keys, depth + 1)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v, keys, depth + 1) for v in value]
    return value


def _to_wire(e: AuditEvent) -> dict:
    """AuditEvent -> the camelCase JSON the API expects."""
    return {
        "auditId": e.audit_id, "agentId": e.agent_id, "userId": e.user_id, "action": e.action,
        "payload": e.payload, "approved": e.approved, "reason": e.reason, "matchedRule": e.matched_rule,
        "tags": e.tags, "timestamp": e.timestamp, "environment": e.environment, "sdkVersion": e.sdk_version,
    }
WAITLIST_URL = "https://auditail.io/waitlist"


class Auditail:
    """
    Auditail client. Instantiate once at app startup and reuse.

    Example::

        from auditail import Auditail, rules

        auditail = Auditail(api_key="your_key")
        auditail.add_rule(rules.no_external_email())
        auditail.add_rule(rules.no_data_deletion())

        result = auditail.guard(
            action="send_email",
            payload={"to": "client@example.com", "body": "Report attached."},
            agent_id="financial-bot-01",
        )

        if result.approved:
            send_email(...)
    """

    def __init__(
        self,
        api_key: str,
        environment: str = "production",
        log_level: str = "info",
        base_url: str = "https://api.auditail.io",
        redact_keys: Optional[Iterable[str]] = None,
        ship: bool = True,
        flush_interval: float = 1.0,
        on_error: Optional[Callable[[Exception], None]] = None,
        approval_timeout_seconds: int = 900,
        on_approval_requested: Optional[Callable[[dict], None]] = None,
        server_policy: bool = False,
        freeze_check_interval: float = 10.0,
    ):
        if not api_key:
            raise ValueError(
                f"[Auditail] No API key provided.\nGet your free API key at: {WAITLIST_URL}"
            )

        self.api_key = api_key
        self.environment = environment
        self.log_level = log_level
        self.base_url = base_url.rstrip("/")
        self.ship = ship
        self.flush_interval = flush_interval
        self._extra_redact: List[str] = [k.lower() for k in (redact_keys or [])]
        self._redact = DEFAULT_REDACT | set(self._extra_redact)
        self._account_id: Optional[str] = None
        self._on_error = on_error or (lambda e: self._log("error", str(e)))
        self.approval_timeout_seconds = approval_timeout_seconds
        self._on_approval_requested = on_approval_requested
        # Also enforce the server-side policy approvers manage in Auditail (allowed actions, limits, provenance,
        # approval thresholds). One network call per action; denies if Auditail cannot be reached.
        self.server_policy = server_policy
        # Kill switch in local mode: how often to refresh freeze status (seconds; 0 disables).
        self.freeze_check_interval = freeze_check_interval
        self._freezes: List[Dict[str, Any]] = []
        self._freeze_checked_at = 0.0
        self._freeze_lock = threading.Lock()

        self._rules: List[GuardrailRule] = []
        self._audit_log: List[AuditEvent] = []

        self._queue: Deque[AuditEvent] = deque()
        self._qlock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None
        if ship:
            atexit.register(self.flush)

    def add_rule(self, rule: GuardrailRule) -> "Auditail":
        """Register a guardrail rule. Rules are evaluated in registration order."""
        self._rules.append(rule)
        self._log("debug", f'Guardrail rule added: "{rule.name}"')
        return self

    def add_rules(self, rules: List[GuardrailRule]) -> "Auditail":
        """Register multiple guardrail rules at once."""
        for rule in rules:
            self.add_rule(rule)
        return self

    def guard(
        self,
        action: str,
        payload: dict,
        agent_id: str,
        user_id: Optional[str] = None,
        tags: Optional[dict] = None,
        wait: bool = True,
        source: Optional[str] = None,
        field_sources: Optional[Dict[str, str]] = None,
        intent: Optional[str] = None,
        user_request: Optional[str] = None,
        session_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
        callback_url: Optional[str] = None,
    ) -> GuardResult:
        """
        Synchronous guard evaluation.
        Evaluates the action against all registered rules and records an audit event.

        If a ``require_approval`` rule fires, this blocks until a human decides (or the approval times out,
        which denies). Pass ``wait=False`` to return immediately with ``pending=True`` and call
        ``wait_for_approval(result.approval.id)`` later.
        """
        opts = GuardOptions(
            action=action,
            payload=payload,
            agent_id=agent_id,
            user_id=user_id,
            tags=tags,
            wait=wait,
            source=source,
            field_sources=field_sources,
            intent=intent,
            user_request=user_request,
            session_id=session_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            callback_url=callback_url,
        )
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self._evaluate(opts))
        # Already inside a running event loop (FastAPI, async LangChain):
        # run the evaluation on a worker thread so we don't crash or block the loop's state.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, self._evaluate(opts)).result()

    async def guard_async(
        self,
        action: str,
        payload: dict,
        agent_id: str,
        user_id: Optional[str] = None,
        tags: Optional[dict] = None,
        wait: bool = True,
        source: Optional[str] = None,
        field_sources: Optional[Dict[str, str]] = None,
        intent: Optional[str] = None,
        user_request: Optional[str] = None,
        session_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        correlation_id: Optional[str] = None,
        callback_url: Optional[str] = None,
    ) -> GuardResult:
        """
        Async guard evaluation for use in async codebases (FastAPI, etc.).
        See ``guard`` for the ``wait`` option.
        """
        opts = GuardOptions(
            action=action,
            payload=payload,
            agent_id=agent_id,
            user_id=user_id,
            tags=tags,
            wait=wait,
            source=source,
            field_sources=field_sources,
            intent=intent,
            user_request=user_request,
            session_id=session_id,
            idempotency_key=idempotency_key,
            correlation_id=correlation_id,
            callback_url=callback_url,
        )
        return await self._evaluate(opts)

    def get_audit_log(self) -> List[AuditEvent]:
        """
        Returns all audit events from this session.
        For the persistent, tamper-evident log across processes, use the dashboard at https://app.auditail.io.
        """
        return list(self._audit_log)

    # ---------------------------------------------------------------------------
    # Private
    # ---------------------------------------------------------------------------

    async def _evaluate(self, opts: GuardOptions) -> GuardResult:
        start = time.monotonic()
        audit_id = self._generate_id()
        self._log("debug", f'Evaluating action "{opts.action}" for agent "{opts.agent_id}"')

        d: Dict[str, Any] = {"approved": True, "code": "allowed", "decided_by": "rule"}
        approval_rule: Optional[GuardrailRule] = None

        # 0. Kill switch (local mode). With server_policy, the server enforces it on every call.
        if not self.server_policy:
            f = await asyncio.to_thread(self._active_freeze, opts.agent_id, opts.action)
            if f:
                what = "All agents are" if f["scope"] == "all" else (f'Agent "{f["target"]}" is' if f["scope"] == "agent" else f'Action "{f["target"]}" is')
                d = {"approved": False, "code": "frozen", "decided_by": "policy", "matched_rule": "kill-switch",
                     "reason": f"{what} frozen by {f['createdBy']} since {f['createdAt']}: {f['reason']}",
                     "hint": "Stop and tell the user. An approver must lift the freeze before this can run; retrying will not help."}

        # 1. Local rules: instant, in-process.
        for rule in (self._rules if d["approved"] else []):
            try:
                result = rule.condition(opts)
                triggered = await result if inspect.isawaitable(result) else result
            except Exception as exc:
                # Fail closed: a rule that cannot be evaluated blocks the action outright. It never asks a human,
                # so a coding bug cannot page approvers or stall the agent until the approval times out.
                self._log("error", f'Rule "{rule.name}" raised {exc!r}. Failing closed (blocking action).')
                d = {"approved": False, "code": "rule_error", "decided_by": "rule", "matched_rule": rule.name,
                     "reason": f'Blocked: rule "{rule.name}" could not be evaluated ({exc!r:.200}).',
                     "hint": "This is a bug in a guardrail rule, not something the agent can fix. Report it."}
                break
            if not triggered:
                continue
            if rule.action == "block":
                self._log("warn", f'Action BLOCKED by rule "{rule.name}": {rule.description}')
                d = {"approved": False, "code": rule.code or "rule_blocked", "decided_by": "rule", "matched_rule": rule.name,
                     "reason": rule.description, "hint": rule.hint}
                break
            if rule.action == "require_approval":
                approval_rule = rule
                d["matched_rule"] = rule.name
                break
            if rule.action == "alert":
                self._log("warn", f'ALERT fired by rule "{rule.name}": {rule.description}')
                d.setdefault("matched_rule", rule.name)

        # 2. Server-side policy and/or human approval.
        if d["approved"]:
            if self.server_policy:
                d = await self._policy_flow(opts, approval_rule, d.get("matched_rule"))
            elif approval_rule:
                self._log("warn", f'Approval REQUIRED by rule "{approval_rule.name}": {approval_rule.description}')
                d = await self._approval_flow(opts, approval_rule)

        latency_ms = int((time.monotonic() - start) * 1000)
        timestamp = datetime.now(timezone.utc).isoformat()
        approval: Optional[GuardApproval] = d.get("approval")
        event = AuditEvent(
            audit_id=d.get("server_audit_id") or audit_id,
            agent_id=opts.agent_id,
            user_id=opts.user_id,
            action=opts.action,
            payload=_redact(opts.payload, self._redact),
            approved=d["approved"],
            reason=d.get("reason"),
            matched_rule=d.get("matched_rule"),
            tags=opts.tags,
            timestamp=timestamp,
            environment=self.environment,
            sdk_version=SDK_VERSION,
            approval_id=approval.id if approval else None,
        )
        self._audit_log.append(event)
        status = "PENDING" if d.get("pending") else ("APPROVED" if d["approved"] else "BLOCKED")
        self._log("info", f"[{status}] {opts.action} ({d['code']}) | auditId: {event.audit_id} | {latency_ms}ms")

        # Decisions made by the server (policy, human approval) are recorded there. Everything else ships in the background.
        if not d.get("server_recorded"):
            self._ship_to_api(event)

        return GuardResult(
            approved=d["approved"],
            audit_id=event.audit_id,
            reason=d.get("reason"),
            matched_rule=d.get("matched_rule"),
            timestamp=timestamp,
            latency_ms=latency_ms,
            approval=approval,
            pending=bool(d.get("pending")),
            code=d["code"],
            hint=d.get("hint"),
            decided_by=d["decided_by"],
            receipt=d.get("receipt"),
            limits=d.get("limits"),
            shadow=d.get("shadow"),
        )

    async def _policy_flow(self, opts: GuardOptions, approval_rule: Optional[GuardrailRule], matched_rule: Optional[str]) -> Dict[str, Any]:
        def unavailable(why: str) -> Dict[str, Any]:
            return {"approved": False, "code": "policy_unavailable", "decided_by": "policy", "matched_rule": matched_rule,
                    "reason": f"Server-side policy could not be checked ({why}); action denied.",
                    "hint": "Retry later. Actions are never allowed when the policy cannot be checked."}

        if not self.ship:
            return unavailable("shipping is disabled")
        body: Dict[str, Any] = {
            "action": opts.action, "agentId": opts.agent_id, "payload": _redact(opts.payload, self._redact),
            "userId": opts.user_id, "tags": opts.tags, "environment": self.environment,
            "source": opts.source, "fieldSources": opts.field_sources, "intent": opts.intent, "userRequest": opts.user_request,
            "timeoutSeconds": (approval_rule.approval_timeout_seconds if approval_rule and approval_rule.approval_timeout_seconds else self.approval_timeout_seconds),
            "sessionId": opts.session_id, "correlationId": opts.correlation_id, "callbackUrl": opts.callback_url,
            # One key per guard() call: network retries inside this call can't open a second approval or count usage twice.
            "idempotencyKey": opts.idempotency_key or f"gk_{uuid.uuid4().hex[:16]}",
        }
        if approval_rule:
            body["requireApproval"] = {"ruleName": approval_rule.name, "reason": approval_rule.description}
        body = {k: v for k, v in body.items() if v is not None}
        ok, p, status, error = await asyncio.to_thread(self._api_sync, "POST", "/v1/decide", body)
        if not ok:
            self._on_error(RuntimeError(f"Auditail policy check failed: {error}"))
            return unavailable("invalid API key" if status == 401 else "Auditail could not be reached")

        base = {"decided_by": "policy", "server_recorded": True, "server_audit_id": p.get("auditId") or p.get("decisionId"), "limits": p.get("limits")}
        if p["decision"] == "allow":
            return {**base, "approved": True, "code": p["code"], "reason": p["reason"], "receipt": p.get("receipt"), "matched_rule": matched_rule, "shadow": p.get("shadow")}
        if p["decision"] == "deny":
            return {**base, "approved": False, "code": p["code"], "reason": p["reason"], "hint": p.get("hint"), "matched_rule": f"policy:{p['code']}"}

        a = p["approval"]  # require_approval: the server already opened the request
        self._log("warn", f"Approval REQUIRED by policy ({p['code']}): {p['reason']}")
        if self._on_approval_requested:
            try:
                self._on_approval_requested(a)
            except Exception as exc:  # never let a notification bug reach the agent
                self._on_error(exc)
        if not opts.wait:
            return {**base, "approved": False, "pending": True, "code": "approval_pending", "hint": p.get("hint"),
                    "reason": f"{p['reason']} Awaiting a human ({a['id']}); not approved yet.",
                    "approval": GuardApproval(id=a["id"], status="pending"), "matched_rule": f"policy:{p['code']}"}
        final = await asyncio.to_thread(self.wait_for_approval, a["id"])
        out = self._final_from_approval(final, f"policy:{p['code']}", p["reason"])
        out["server_audit_id"] = base["server_audit_id"]
        out["limits"] = base["limits"]
        return out

    @staticmethod
    def _final_from_approval(final: GuardApproval, matched_rule: str, why: str) -> Dict[str, Any]:
        by = f" by {final.decided_by}" if final.decided_by else ""
        note = f": {final.comment}" if final.comment else ""
        common = {"decided_by": "human", "server_recorded": True, "approval": final, "matched_rule": matched_rule}
        if final.status == "approved":
            return {**common, "approved": True, "code": "approved_by_human", "reason": f"Approved{by}{note}", "receipt": final.receipt}
        if final.status == "denied":
            return {**common, "approved": False, "code": "approval_denied", "reason": f"Denied{by}{note}",
                    "hint": "A human rejected this action. Do not retry it unchanged; ask the user how to proceed."}
        if final.status == "expired":
            return {**common, "approved": False, "code": "approval_expired", "reason": "Approval expired without a decision; action denied.",
                    "hint": "Nobody responded in time. Ask the user to get it approved, then retry."}
        return {**common, "decided_by": "policy", "server_recorded": False, "approved": False, "code": "approval_unavailable",
                "reason": f"{why} The decision could not be confirmed; action denied.", "hint": "Retry later."}

    def wait_for_approval(self, approval_id: str, timeout_seconds: Optional[float] = None) -> GuardApproval:
        """
        Block until a pending approval is decided and return the final status.
        Never raises. If Auditail cannot be reached until the deadline the status is 'unavailable',
        which you must treat as denied.
        """
        started = time.monotonic()
        deadline = started + timeout_seconds if timeout_seconds is not None else float("inf")
        while True:
            ok, value, status, error = self._api_sync("GET", f"/v1/approvals/{approval_id}")
            if ok:
                if value["status"] != "pending":
                    return GuardApproval(id=value["id"], status=value["status"], decided_by=value.get("decidedBy"),
                                         comment=value.get("comment"), receipt=value.get("receipt"))
                # the server expires it at expiresAt; allow a short grace period for the final answer to be readable
                exp = datetime.fromisoformat(value["expiresAt"].replace("Z", "+00:00")).timestamp()
                deadline = min(deadline, time.monotonic() + (exp - time.time()) + 15)
            elif status in (401, 403, 404):
                self._on_error(RuntimeError(f"Auditail could not read approval {approval_id}: {error}"))
                return GuardApproval(id=approval_id, status="unavailable")
            if time.monotonic() >= deadline:
                return GuardApproval(id=approval_id, status="unavailable")
            base = 2.0 if time.monotonic() - started < 60 else 5.0
            time.sleep(base * (0.8 + random.random() * 0.4))

    def checkpoint(self) -> Optional[str]:
        """
        A signed checkpoint of your audit log's current state. Store it anywhere you control: if the log is ever
        rewritten, `auditail-verify --checkpoint` will show it. Returns None if the log is empty or unreachable.
        """
        ok, value, _status, _error = self._api_sync("GET", "/v1/checkpoint")
        return value["checkpoint"] if ok else None

    async def _approval_flow(self, opts: GuardOptions, rule: GuardrailRule) -> Dict[str, Any]:
        def denied(why: str, approval_id: str = "") -> Dict[str, Any]:
            return {"approved": False, "code": "approval_unavailable", "decided_by": "rule", "matched_rule": rule.name,
                    "reason": f'Approval required by "{rule.name}" but {why}; action denied.',
                    "hint": "Retry later. Actions that need approval never proceed without one.",
                    "approval": GuardApproval(id=approval_id, status="unavailable")}

        if not self.ship:
            return denied("approvals need a connection to Auditail (shipping is disabled)")
        body = {
            "agentId": opts.agent_id, "action": opts.action, "ruleName": rule.name, "reason": rule.description,
            "payload": _redact(opts.payload, self._redact), "userId": opts.user_id, "tags": opts.tags,
            "environment": self.environment, "timeoutSeconds": rule.approval_timeout_seconds or self.approval_timeout_seconds,
            "receiptTtlSeconds": rule.receipt_ttl_seconds, "intent": opts.intent, "userRequest": opts.user_request, "source": opts.source,
            "correlationId": opts.correlation_id, "callbackUrl": opts.callback_url,
            "idempotencyKey": opts.idempotency_key or f"gk_{uuid.uuid4().hex[:16]}",
        }
        body = {k: v for k, v in body.items() if v is not None}
        ok, created, status, error = await asyncio.to_thread(self._api_sync, "POST", "/v1/approvals", body)
        if not ok:
            if status == 423:
                reason = "Agents are frozen."
                try:
                    reason = json.loads(error.split(" ", 2)[2])["error"]["message"]
                except Exception:
                    pass
                return {"approved": False, "code": "frozen", "decided_by": "policy", "matched_rule": "kill-switch", "reason": reason,
                        "hint": "Stop and tell the user. An approver must lift the freeze before this can run; retrying will not help."}
            self._on_error(RuntimeError(f"Auditail could not create the approval request: {error}"))
            return denied("Auditail could not be reached")

        self._log("info", f"Approval {created['id']} requested; waiting for a human (expires {created['expiresAt']})")
        if self._on_approval_requested:
            try:
                self._on_approval_requested(created)
            except Exception as exc:  # never let a notification bug reach the agent
                self._on_error(exc)
        if not opts.wait:
            return {"approved": False, "pending": True, "code": "approval_pending", "decided_by": "rule", "server_recorded": True,
                    "matched_rule": rule.name, "reason": f"Awaiting human approval ({created['id']}); not approved yet.",
                    "approval": GuardApproval(id=created["id"], status="pending")}
        final = await asyncio.to_thread(self.wait_for_approval, created["id"])
        if final.status == "unavailable":
            return denied("the decision could not be confirmed", created["id"])
        return self._final_from_approval(final, rule.name, f'Approval required by "{rule.name}".')

    def _active_freeze(self, agent_id: str, action: str) -> Optional[Dict[str, Any]]:
        if self.freeze_check_interval > 0 and self.ship and time.monotonic() - self._freeze_checked_at > self.freeze_check_interval:
            with self._freeze_lock:
                if time.monotonic() - self._freeze_checked_at > self.freeze_check_interval:
                    ok, value, _s, _e = self._api_sync("GET", "/v1/freeze")
                    if ok:
                        self._freezes = value.get("active", [])
                    self._freeze_checked_at = time.monotonic()
        for f in self._freezes:
            if f["scope"] == "all" or (f["scope"] == "agent" and f.get("target") == agent_id) or (f["scope"] == "action" and f.get("target") == action):
                return f
        return None

    # ---------------------------------------------------------------------------
    # Agent runtime: plan, pause/resume, outcomes, session taint
    # ---------------------------------------------------------------------------

    def simulate(
        self,
        action: str,
        payload: dict,
        agent_id: str,
        user_id: Optional[str] = None,
        source: Optional[str] = None,
        field_sources: Optional[Dict[str, str]] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dry run: what would the policy decide for this action right now? Nothing is recorded, reserved or sent
        for approval. A prediction, not a reservation: guard() still decides. Returns the decision dict
        (decision is "allow", "deny", "require_approval", or "unavailable" if Auditail could not be reached)."""
        body = {"action": action, "agentId": agent_id, "payload": _redact(payload, self._redact), "userId": user_id,
                "environment": self.environment, "source": source, "fieldSources": field_sources, "sessionId": session_id, "dryRun": True}
        # A separate path, so a server without dry runs answers 404 instead of making a real decision.
        ok, value, _status, error = self._api_sync("POST", "/v1/decide/dry-run", {k: v for k, v in body.items() if v is not None})
        if not ok:
            return {"dryRun": True, "decision": "unavailable", "code": "policy_unavailable", "reason": f"Auditail could not be reached: {error}"}
        return value

    def get_capabilities(
        self,
        agent_id: Optional[str] = None,
        action: Optional[str] = None,
        payload: Optional[dict] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """What may this agent do, and how much budget is left? Read-only: allowed actions, approval thresholds,
        first-time rules and remaining limits (pass action and payload to see per-beneficiary or per-currency budgets).
        Raises RuntimeError if unavailable or disabled by policy."""
        body = {"agentId": agent_id, "action": action, "payload": payload, "sessionId": session_id}
        ok, value, _status, error = self._api_sync("POST", "/v1/capabilities", {k: v for k, v in body.items() if v is not None})
        if not ok:
            raise RuntimeError(f"Auditail capabilities unavailable: {error}")
        return value

    def mark_untrusted(self, session_id: str, source: str, note: Optional[str] = None) -> Dict[str, Any]:
        """Mark a session as having read untrusted content (an inbound email, a web page, an uploaded PDF). From then
        on, money-moving actions in this session need a human (per policy), until it expires (24 h) or an approver clears it."""
        body = {"source": source, **({"note": note} if note else {})}
        ok, value, _status, error = self._api_sync("POST", f"/v1/sessions/{urllib.parse.quote(session_id, safe='')}/taint", body)
        if not ok:
            raise RuntimeError(f"Auditail could not record the taint: {error}")
        return value

    def resume(self, approval_id: str) -> Dict[str, Any]:
        """Pause/resume: check an approval once, without waiting. Call it when your workflow wakes up (callback,
        signal or event). Returns {"status", "approved", "pending", "code", "reason", "receipt"?, "approval"?}."""
        ok, a, _status, error = self._api_sync("GET", f"/v1/approvals/{urllib.parse.quote(approval_id, safe='')}")
        if not ok:
            return {"status": "unavailable", "approved": False, "pending": False, "code": "approval_unavailable", "reason": f"Could not read the approval: {error}"}
        if a["status"] == "pending":
            return {"status": "pending", "approved": False, "pending": True, "code": "approval_pending", "reason": "Still waiting for a human.", "approval": a}
        final = GuardApproval(id=a["id"], status=a["status"], decided_by=a.get("decidedBy"), comment=a.get("comment"), receipt=a.get("receipt"))
        d = self._final_from_approval(final, "approval", "")
        return {"status": a["status"], "approved": d["approved"], "pending": False, "code": d["code"], "reason": d["reason"],
                "receipt": a.get("receipt"), "approval": a}

    def report_outcome(
        self,
        status: str,
        audit_id: Optional[str] = None,
        receipt: Optional[str] = None,
        external_tx_id: Optional[str] = None,
        amount: Optional[float] = None,
        currency: Optional[str] = None,
        reason: Optional[str] = None,
        compensates: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record what happened after authorization: "settled", "failed", "reversed", "refunded" or "voided", linked to
        the decision (audit_id or receipt). Use compensates to link a refund or reversal decision to the original.
        Reports made with an approver token are trusted: "failed" and "voided" give the budget back. Agent reports are
        recorded only. Raises RuntimeError on failure."""
        body = {"status": status, "auditId": audit_id, "receipt": receipt, "externalTxId": external_tx_id, "amount": amount,
                "currency": currency, "reason": reason, "compensates": compensates}
        ok, value, _status, error = self._api_sync("POST", "/v1/outcomes", {k: v for k, v in body.items() if v is not None})
        if not ok:
            raise RuntimeError(f"Auditail could not record the outcome: {error}")
        return value

    def check_receipt(
        self,
        receipt: Optional[str],
        action: str,
        payload: Dict[str, Any],
        account: Optional[str] = None,
        public_keys: Optional[List[Dict[str, Any]]] = None,
        require_human_approval: bool = False,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """One call for the service that executes an action: verify the receipt, then redeem it once.

        Returns {"ok": True, "claims": ..., "redeemedAt": ...} only when it is safe to execute, otherwise
        {"ok": False, "code": ..., "reason": ...}. Needs: pip install "auditail[verify]".
        """
        if not receipt:
            return {"ok": False, "code": "missing_receipt", "reason": "No Auditail receipt was provided."}
        from .verify import verify_receipt  # imported here: verify needs the optional cryptography package

        acct = account or getattr(self, "_account_id", None)
        if not acct:
            ok, me, _status, error = self._api_sync("GET", "/v1/me")
            if not ok:
                return {"ok": False, "code": "unavailable", "reason": f"Could not reach Auditail to identify the account: {error}"}
            acct = self._account_id = me["keyId"]
        v = verify_receipt(
            receipt, account=acct, action=action, payload=payload, redact_keys=self._extra_redact or None,
            public_keys=public_keys, keys_url=f"{self.base_url}/.well-known/auditail-keys.json",
            require_human_approval=require_human_approval,
        )
        if not v.valid:
            return {"ok": False, "code": "invalid_receipt", "reason": v.reason or "invalid receipt"}
        r = self.redeem_receipt(receipt, action=action, request_id=request_id)
        if not r["redeemed"]:
            return {"ok": False, "code": r["code"], "reason": r["message"]}
        return {"ok": True, "claims": v.claims, "redeemedAt": r["redeemedAt"]}

    def redeem_receipt(self, receipt: str, action: Optional[str] = None, request_id: Optional[str] = None) -> Dict[str, Any]:
        """Mark a receipt as used, so the action it approves runs at most once.

        Call it in the service that executes the action, after verify_receipt() has checked the payload.
        Retries reuse the same request id, so they are safe. Returns {"redeemed": True, ...} or
        {"redeemed": False, "code": ..., "message": ...}; when redeemed is False, do not execute the action.
        """
        body: Dict[str, Any] = {"receipt": receipt, "requestId": request_id or f"rdm_{uuid.uuid4().hex[:16]}"}
        if action is not None:
            body["action"] = action
        ok, value, _status, error = self._api_sync("POST", "/v1/receipts/redeem", body)
        if ok:
            return {**value, "redeemed": True}
        code, message = "unavailable", error
        try:
            j = json.loads(error.split(" ", 2)[2]) if error.startswith("HTTP ") else {}
            code = j.get("error", {}).get("code", code)
            message = j.get("error", {}).get("message", message)
        except (ValueError, IndexError, AttributeError):
            pass
        return {"redeemed": False, "code": code, "message": message}

    def _api_sync(self, method: str, path: str, body: Optional[dict] = None):
        """Blocking JSON call with small retries. Returns (ok, value, http_status, error)."""
        data = json.dumps(body).encode() if body is not None else None
        last_error = "network error"
        for attempt in range(1, 4):
            req = urllib.request.Request(
                f"{self.base_url}{path}",
                data=data,
                method=method,
                headers={
                    **({"content-type": "application/json"} if data else {}),
                    "authorization": f"Bearer {self.api_key}",
                    "user-agent": f"auditail-python/{SDK_VERSION}",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return True, json.loads(resp.read() or b"{}"), resp.status, ""
            except urllib.error.HTTPError as exc:
                detail = exc.read(1000).decode(errors="replace")
                if exc.code < 500 and exc.code != 429:
                    return False, None, exc.code, f"HTTP {exc.code} {detail}"
                last_error = f"HTTP {exc.code}"
            except Exception as exc:
                last_error = str(exc) or exc.__class__.__name__
            if attempt < 3:
                time.sleep(random.random() * 0.4 * attempt)
        return False, None, 0, last_error

    def _generate_id(self) -> str:
        return f"aeg_{uuid.uuid4().hex[:16]}"

    def _log(self, level: str, message: str) -> None:
        levels = ["debug", "info", "warn", "error", "silent"]
        if level not in levels:
            return
        if levels.index(level) < levels.index(self.log_level):
            return
        prefix = "[Auditail]"
        if level == "warn":
            print(f"{prefix} ⚠️  {message}")
        elif level == "error":
            print(f"{prefix} ❌  {message}")
        else:
            print(f"{prefix} {message}")

    # ---------------------------------------------------------------------------
    # Delivery: non-blocking queue + background worker. Never raises into the caller.
    # ---------------------------------------------------------------------------

    def _ship_to_api(self, event: AuditEvent) -> None:
        if not self.ship:
            return
        with self._qlock:
            if len(self._queue) >= MAX_QUEUE:
                self._queue.popleft()
                self._on_error(RuntimeError(f"Auditail queue full ({MAX_QUEUE}); dropped oldest event"))
            self._queue.append(event)
        self._ensure_worker()
        self._wake.set()

    def _ensure_worker(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._run, name="auditail-shipper", daemon=True)
        self._worker.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=self.flush_interval)
            self._wake.clear()
            self._drain()

    def flush(self) -> None:
        """Deliver all queued events now. Never raises. Call before a serverless handler returns."""
        self._drain()

    def shutdown(self) -> None:
        """Flush and stop the background worker."""
        self._stop.set()
        self._wake.set()
        self.flush()

    def _drain(self) -> None:
        with self._flush_lock:
            while True:
                with self._qlock:
                    batch = list(self._queue)[:MAX_BATCH]
                if not batch:
                    return
                if not self._deliver(batch):
                    return  # keep events queued; the next flush retries
                done = {id(e) for e in batch}
                with self._qlock:
                    self._queue = deque(e for e in self._queue if id(e) not in done)

    def _deliver(self, batch: List[AuditEvent]) -> bool:
        body = json.dumps({"events": [_to_wire(e) for e in batch]}).encode()
        req = urllib.request.Request(
            f"{self.base_url}/v1/events",
            data=body,
            method="POST",
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {self.api_key}",
                # Explicit UA: Cloudflare blocks the default "Python-urllib" signature (error 1010).
                "user-agent": f"auditail-python/{SDK_VERSION}",
            },
        )
        for attempt in range(1, MAX_DELIVERY_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(req, timeout=10):
                    return True
            except urllib.error.HTTPError as exc:
                if 400 <= exc.code < 500 and exc.code != 429:
                    detail = exc.read(1000).decode(errors="replace")
                    self._on_error(RuntimeError(f"Auditail rejected {len(batch)} event(s): HTTP {exc.code} {detail}"))
                    return True  # permanent: drop, don't retry forever
            except Exception:
                pass  # network error: retry
            if attempt < MAX_DELIVERY_ATTEMPTS:
                time.sleep(random.random() * min(0.25 * 2**attempt, 4.0))
        self._on_error(RuntimeError(f"Auditail could not deliver {len(batch)} event(s); will retry on next flush"))
        return False
