from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable, Dict, List, Optional, Union


@dataclass
class GuardOptions:
    """Options for a single guard evaluation."""
    action: str
    payload: Dict[str, Any]
    agent_id: str
    user_id: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    wait: bool = True
    # Where this request's data came from ('user', 'system', 'inbound_email', 'web_page', ...). Set it in your
    # integration code from what you fed the model; never let the model choose it.
    source: Optional[str] = None
    # Per-field origins, e.g. {"beneficiary.iban": "inbound_email"}.
    field_sources: Optional[Dict[str, str]] = None
    # The agent's stated reason, and the user's original request. Both are shown to approvers.
    intent: Optional[str] = None
    user_request: Optional[str] = None
    # Your agent session or conversation id. Once the session has read untrusted data (mark_untrusted(), or an
    # action with an untrusted source), money-moving actions in it need a human, per the policy's taintedSession.
    session_id: Optional[str] = None
    # Makes retries safe: the same key returns the original decision. Generated per call if omitted.
    idempotency_key: Optional[str] = None
    # Pause/resume: your workflow's id for this request, echoed in the approval and its callback.
    correlation_id: Optional[str] = None
    # Pause/resume: HTTPS URL Auditail POSTs to (signed) when a human decides. Use with wait=False.
    callback_url: Optional[str] = None


@dataclass
class GuardApproval:
    """
    The human-approval outcome attached to a GuardResult.

    status is 'pending' | 'approved' | 'denied' | 'expired' | 'unavailable'.
    'unavailable' means Auditail could not be reached to confirm a decision; treat it as denied.
    """
    id: str
    status: str
    decided_by: Optional[str] = None
    comment: Optional[str] = None
    # Signed proof a human approved exactly this action and payload. Present only when approved.
    # Pass it to the system that executes the action; it checks it with auditail.verify.verify_receipt().
    receipt: Optional[str] = None


@dataclass
class GuardResult:
    """Result of a guard evaluation."""
    approved: bool
    audit_id: str
    timestamp: str
    latency_ms: int
    reason: Optional[str] = None
    matched_rule: Optional[str] = None
    approval: Optional[GuardApproval] = None
    # True only when you passed wait=False and the request is still awaiting a human. NOT approved yet.
    pending: bool = False
    # Stable reason code, e.g. 'allowed', 'limit_exceeded', 'action_not_allowed', 'untrusted_source', 'approval_denied'.
    code: str = "allowed"
    # What the agent can do instead, e.g. "4,000 amount left in this 24h window".
    hint: Optional[str] = None
    # Who made the final decision: 'rule', 'policy' or 'human'.
    decided_by: str = "rule"
    # Signed receipt for an allowed action (human approval or server-side policy). Check it with verify_receipt().
    receipt: Optional[str] = None
    # Usage against each server-side limit this action counts toward (server_policy only).
    limits: Optional[List[Dict[str, Any]]] = None
    # Shadow mode: what would have happened if the policy were enforced ({"wouldBe", "code", "reason"}).
    shadow: Optional[Dict[str, Any]] = None


@dataclass
class GuardrailRule:
    """
    A single guardrail rule.

    condition: callable that receives GuardOptions and returns True to BLOCK.
    action: 'block' | 'require_approval' | 'alert'
    """
    name: str
    description: str
    condition: Callable[[GuardOptions], Union[bool, Awaitable[bool]]]
    action: str = "block"  # 'block' | 'require_approval' | 'alert'
    # For 'require_approval': seconds a human has to respond (10 to 86400). Overrides the client default.
    approval_timeout_seconds: Optional[int] = None
    # For 'require_approval': how long the signed receipt stays valid after approval (60 to 86400). Default 900.
    receipt_ttl_seconds: Optional[int] = None
    # Returned as `hint` / `code` when this rule blocks.
    hint: Optional[str] = None
    code: Optional[str] = None


@dataclass
class AuditEvent:
    """A record of a single agent action evaluation."""
    audit_id: str
    agent_id: str
    action: str
    payload: Dict[str, Any]
    approved: bool
    timestamp: str
    environment: str
    sdk_version: str
    user_id: Optional[str] = None
    reason: Optional[str] = None
    matched_rule: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    # Set when the decision was made by a human approval. Auditail records those events itself.
    approval_id: Optional[str] = None
