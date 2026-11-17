# Examples

| Example | What it shows |
|---|---|
| [`refund-prompt-injection`](./refund-prompt-injection) | A support agent reads a prompt-injected email over MCP and tries to refund an attacker. `auditail-mcp-proxy` and session taint stop it. Runs in 2 minutes. |
| [`inngest-payout-approval`](./inngest-payout-approval) | Durable human approval for agent payouts: Inngest `step.waitForEvent` woken by Auditail's signed callback, with idempotent retries and receipts. |
