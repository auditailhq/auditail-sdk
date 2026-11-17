"""
Auditail Python SDK
The security layer for autonomous AI agents.
Guardrails that block risky actions, plus a tamper-evident audit trail.

https://auditail.io/docs
"""

from .client import Auditail
from .types import GuardOptions, GuardResult, GuardApproval, GuardrailRule, AuditEvent
from . import rules

__version__ = "0.11.1"
__all__ = ["Auditail", "GuardOptions", "GuardResult", "GuardApproval", "GuardrailRule", "AuditEvent", "rules"]
