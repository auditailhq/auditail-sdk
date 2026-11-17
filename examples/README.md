# Examples

| Example | What it shows |
|---|---|
| [`refund-prompt-injection`](./refund-prompt-injection) | A support agent reads a prompt-injected email over MCP and tries to refund an attacker. `auditail-mcp-proxy` and session taint stop it. Runs in 2 minutes. |
| [`split-payments-shadow`](./split-payments-shadow) | A $14,700 invoice paid as three payouts under a $5,000 approval threshold. Shadow mode blocks nothing; the shadow drift report finds the split, and you get a risk pack to hand over. |
| [`receipt-bypass`](./receipt-bypass) | An agent skips `guard()` and calls the payout service directly. The service pays only with a valid, unused receipt for exactly that payment. |
| [`vercel-ai-sdk-guarded-tools`](./vercel-ai-sdk-guarded-tools) | Vercel AI SDK tools that ask Auditail first and tell the model why when the answer is no. |
| [`temporal-payout-approval`](./temporal-payout-approval) | Durable human approval in Temporal: a workflow waits on a signal sent from Auditail's signed callback. |
| [`inngest-payout-approval`](./inngest-payout-approval) | The same with Inngest: `step.waitForEvent` woken by the callback. |
| [`langgraph-payout-approval`](./langgraph-payout-approval) | The same in LangGraph (Python): `interrupt()` and `Command(resume=...)`. |

Each one was run end to end against an Auditail server before publishing.
