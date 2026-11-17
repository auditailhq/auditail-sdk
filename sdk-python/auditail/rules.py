"""
Pre-built guardrail rules for common AI agent security scenarios.
"""

from .types import GuardrailRule, GuardOptions


def no_external_email(internal_domains: list[str] | None = None) -> GuardrailRule:
    """
    Block any email action targeting an external domain.

    Args:
        internal_domains: Trusted domains (e.g. ['acme.com']). Emails to any other
                          domain are blocked. If empty, the rule is inactive.
    """
    domains = internal_domains or []

    def condition(opts: GuardOptions) -> bool:
        if not domains:
            return False  # not configured, skip rule
        to = opts.payload.get("to", "")
        if not to:
            return False
        return not any(to.endswith(f"@{d}") for d in domains)

    return GuardrailRule(
        name="no-external-email",
        description="Blocked: sending email to an external domain is not permitted.",
        condition=condition,
        action="block",
    )


def no_data_deletion() -> GuardrailRule:
    """Block destructive SQL operations (DELETE, DROP, TRUNCATE)."""

    def condition(opts: GuardOptions) -> bool:
        query = str(opts.payload.get("query", "")).upper()
        return any(kw in query for kw in ["DELETE", "DROP TABLE", "TRUNCATE"])

    return GuardrailRule(
        name="no-data-deletion",
        description="Blocked: destructive data operations are not permitted.",
        condition=condition,
        action="block",
    )


def no_external_api_calls() -> GuardrailRule:
    """Alert when an agent makes an outbound HTTP request."""

    def condition(opts: GuardOptions) -> bool:
        return opts.action == "http_request"

    return GuardrailRule(
        name="no-external-api-calls",
        description="Alert: agent is making a call to an external API.",
        condition=condition,
        action="alert",
    )


def no_pii_in_logs() -> GuardrailRule:
    """Block actions that appear to include PII (email addresses, phone numbers) in payloads."""
    import re

    EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    PHONE_RE = re.compile(r"\b(\+?\d[\d\s\-().]{7,}\d)\b")

    def condition(opts: GuardOptions) -> bool:
        payload_str = str(opts.payload)
        return bool(EMAIL_RE.search(payload_str) or PHONE_RE.search(payload_str))

    return GuardrailRule(
        name="no-pii-in-logs",
        description="Alert: payload appears to contain PII (email or phone number).",
        condition=condition,
        action="alert",
    )
