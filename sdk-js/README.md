# auditail-sdk

> **Get your money-moving AI agent to production.** Hard limits the agent can't change, a person on risky payments, every payment matched to what settled, and a signed risk pack your risk team, sponsor bank or auditor can verify.

**[📖 Full Documentation](https://auditail.io/docs)** · **[🚀 Join the Private Beta](https://auditail.io/waitlist)**

---

## Install

```bash
npm install auditail-sdk
```

```bash
pip install auditail  # Python SDK
```

## Quickstart: limits and approval for a payout tool

An approver saves a policy once (dashboard or `PUT /v1/policy`); the agent can't change it:

```json
{
  "defaultAction": "deny",
  "actions": {
    "create_payout": {
      "requireApproval": [{ "field": "amount", "op": ">", "value": 10000 }],
      "limits": [{ "name": "daily-total", "window": "24h", "sum": "amount", "max": 25000, "onExceed": "deny" }]
    }
  }
}
```

The agent checks every payout before it runs:

```typescript
import { Auditail } from 'auditail-sdk';

const auditail = new Auditail({ apiKey: process.env.AUDITAIL_API_KEY!, serverPolicy: true });

const payout = { amount: 9999, beneficiary: { id: 'ben_7' } };
const result = await auditail.guard({ action: 'create_payout', payload: payout, agentId: 'payout-agent' });

if (result.approved) {
  await payments.createPayout(payout, { auditailReceipt: result.receipt }); // your payment client
} else {
  console.log(result.code, result.reason);
  // Third $9,999 payout today:
  // limit_exceeded Denied: limit "daily-total" would be exceeded (29,997 of 25,000 in 24h).
}
```

Payouts over $10,000 wait for a human to approve in the dashboard or via your webhook. Any other action is refused. Every decision goes into a tamper-evident audit log.

Step-by-step, with OpenAI Agents SDK and LangChain examples: [Tutorial: secure a payout tool](https://auditail.io/docs/guides/payout-agent-tutorial).

## MCP tools

Put `auditail-mcp-proxy` in front of any stdio MCP server, and every `tools/call` is checked against your policy before it reaches the server:

```bash
AUDITAIL_API_KEY=atl_live_... npx -p auditail-sdk auditail-mcp-proxy --config auditail-mcp.json -- npx -y @acme/payments-mcp
```

Settlement checks (authorized vs settled), approver signatures and per-payment evidence bundles: [Settlement and evidence](https://auditail.io/docs/guides/settlement-and-evidence).

Dry runs, remaining budget, pause and resume for Temporal, Inngest and LangGraph, settlement outcomes and session taint: [Agent runtime guide](https://auditail.io/docs/guides/agent-runtime).

## Private beta

The SDK, API and dashboard are live. Guardrail rules run locally in your process; every decision is delivered in the background to a **hash-chained audit log** you can browse and verify at [app.auditail.io](https://app.auditail.io).

- Batched, retried, idempotent delivery of events. With local rules only, `guard()` doesn't wait on the network and a delivery failure never reaches your agent. With `serverPolicy`, `guard()` asks the server and fails closed if it can't be reached.
- Secrets are redacted before an event leaves your process (`password`, `token`, `apiKey`, ... plus your own `redactKeys`).
- Call `await auditail.flush()` before a serverless function returns or the process exits.

**[Request an API key](https://auditail.io/waitlist)**: keys are issued to design partners personally.

**Human approval** is live: a `require_approval` rule pauses the agent until someone approves or denies it in the dashboard or through your webhook (Slack, Teams, Discord, any HTTPS endpoint). No answer means denied. See the [approval guide](https://auditail.io/docs/guides/human-approval).

**Server-side policies:** allowed actions with everything else denied, spending and rate limits counted atomically on the server, rules for data from untrusted sources, and reason codes with hints the agent can act on. Approvers write them; agents can't change them. See [policies](https://auditail.io/docs/guides/policies).

**Signed receipts:** every human approval returns a receipt your payment or email service can verify before acting (`verifyReceipt`), so an agent cannot skip the check. Logs export to a file anyone can verify offline: `npx -p auditail-sdk auditail-verify`. See [receipts and evidence](https://auditail.io/docs/guides/receipts-and-evidence).

**Kill switch, shadow mode and examiner reports:** freeze every agent, one agent or one action; try a policy in shadow mode or backtest it on recorded traffic; download a signed report for your examiners. See [kill switch and reports](https://auditail.io/docs/guides/kill-switch-and-reports).

**Roadmap** (not available yet): native Slack and PagerDuty apps, private-cloud deployment.

## License

MIT
