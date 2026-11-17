"""
Auditail Python SDK — Quick Example
Run: python example.py
"""

from auditail import Auditail, rules


def main():
    # 1. Initialize
    aegis = Auditail(api_key="auditail_demo_key_123", environment="staging")

    # 2. Add guardrail rules
    aegis.add_rules([
        rules.no_external_email(internal_domains=["yourdomain.com"]),
        rules.no_data_deletion(),
        rules.no_external_api_calls(),
        rules.no_pii_in_logs(),
    ])

    # 3. Test: approved action
    print("\n--- Test 1: Internal email (should be APPROVED) ---")
    result = aegis.guard(
        action="send_email",
        payload={"to": "teammate@yourdomain.com", "subject": "Weekly Report"},
        agent_id="report-bot-01",
    )
    print(f"approved={result.approved}, auditId={result.audit_id}")

    # 4. Test: blocked (external email)
    print("\n--- Test 2: External email (should be BLOCKED) ---")
    result = aegis.guard(
        action="send_email",
        payload={"to": "client@externalco.com", "subject": "Invoice"},
        agent_id="billing-bot-01",
        user_id="user_42",
    )
    print(f"approved={result.approved}, reason={result.reason}")

    # 5. Test: blocked (db deletion)
    print("\n--- Test 3: DB deletion (should be BLOCKED) ---")
    result = aegis.guard(
        action="execute_query",
        payload={"query": "DELETE FROM users WHERE inactive = true"},
        agent_id="db-cleanup-bot",
        tags={"team": "data-engineering"},
    )
    print(f"approved={result.approved}, reason={result.reason}")

    # 6. Audit log
    print("\n--- Audit Log ---")
    for event in aegis.get_audit_log():
        status = "✅ APPROVED" if event.approved else "🚫 BLOCKED"
        print(f"  {status} | {event.action} | {event.agent_id} | {event.audit_id}")


if __name__ == "__main__":
    main()
