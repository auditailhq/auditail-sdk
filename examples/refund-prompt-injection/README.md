# A prompt-injected refund, stopped

A support agent reads a customer email over MCP. The email hides an instruction: refund $180 to the attacker's
account. The agent obeys. This example shows the refund going through, then shows the same agent behind
`auditail-mcp-proxy`, where it doesn't.

The agent here is a script that does what the injected text says, so the demo is the same every run. Real models
follow injected instructions often enough that you can't rely on them not to.

## Run it (about 2 minutes)

```bash
npm install
npm run attack        # agent -> MCP server directly
#   [support-desk] REFUND EXECUTED: 180 USD to acct_attacker_9921
#   RESULT: the injected refund WAS executed.
```

Now protect it:

1. Create a free account at [app.auditail.io](https://app.auditail.io) (email link; you get an agent key and an approver token).
2. Sign in with the approver token, open **Policy**, paste [`policy.json`](./policy.json) and save.
3. Run the agent through the proxy:

```bash
AUDITAIL_API_KEY=atl_live_... npm run protected
#   > issue_refund({"amount":180,...})
#     [tool error] Not executed: this needs human approval in Auditail (apr_...). Needs approval: this session read
#     untrusted data (inbound_email: MCP tool read_inbox) since ...
#   RESULT: the injected refund was NOT executed.
```

## Why it was stopped

$180 is under the $200 approval threshold, so an amount rule alone would have let it through. What stopped it is
**session taint**:

- [`auditail-mcp.json`](./auditail-mcp.json) marks `read_inbox` as `"untrusted": "inbound_email"`. Calling it marks the session as having read outside content.
- The policy's `"taintedSession": "require_approval"` says money-moving actions in such a session need a human.
- The refund waits in the dashboard (or [Slack](https://auditail.io/docs/guides/human-approval)). A person sees the email-driven refund to an unknown account and denies it.

Taint is deliberately coarse: after the agent reads the email, a legitimate $48 refund in the same session needs a
human too. Start a fresh session for work that shouldn't inherit it.

## Files

| File | What it is |
|---|---|
| `support-mcp-server.mjs` | A stdio MCP server with `read_inbox`, `get_order`, `issue_refund`. The inbox contains the injection. |
| `agent.mjs` | The scripted agent. `--direct` skips the proxy. |
| `auditail-mcp.json` | Proxy config: which tools are read-only, which content is untrusted, how refund arguments map to the policy. |
| `policy.json` | Default-deny, refunds over $200 need a human, a $2,000 daily refund cap, tainted sessions need a human. |

More: [MCP proxy](https://auditail.io/docs/guides/agent-runtime#mcp-proxy), [session taint](https://auditail.io/docs/guides/agent-runtime#session-taint-after-untrusted-content).
