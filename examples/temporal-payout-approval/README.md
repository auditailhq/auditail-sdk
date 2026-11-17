# Durable human approval for agent payouts (Temporal + Auditail)

A Temporal workflow asks Auditail before paying. Small payouts are allowed by your policy at once. Large ones wait for
a person, for minutes or days: the workflow sleeps on `condition()`, survives worker restarts, and wakes when Auditail's
signed callback is turned into a Temporal **signal**.

```
POST /payout -> payoutWorkflow
  requestDecision (activity: guard, wait: false) --allowed--> executePayout -> reportOutcome
        | pending
        v
  condition(() => decided, '24 hours')  <-- signal approvalDecided <-- /auditail/callback <-- Auditail (signed)
        v
  readDecision (activity: resume) --approved--> executePayout -> reportOutcome
                                  --denied----> { status: 'not_approved' }
```

| File | What it does |
|---|---|
| `src/workflows.ts` | The workflow. Deterministic: no network calls, only activities, a signal and a durable wait. |
| `src/activities.ts` | `guard()`, `resume()`, your payment call and the outcome report. |
| `src/server.ts` | Starts workflows; verifies Auditail's callback signature and signals the workflow. |
| `src/worker.ts` | The Temporal worker. |

## Run it

1. Create an Auditail account, sign in with the approver token, paste [`policy.json`](./policy.json) into **Policy** and save (payouts over $1,000 need a human).
2. Create the callback signing secret once: `PUT /v1/settings {"rotateSecret": true}` with your approver token; keep `signingSecret`.
3. Callbacks must reach you over public HTTPS; locally use a tunnel (for example `cloudflared tunnel --url http://localhost:3000`).

```bash
npm install
temporal server start-dev                       # Temporal's local dev server
export AUDITAIL_API_KEY=atl_live_... AUDITAIL_WEBHOOK_SECRET=... PUBLIC_URL=https://<your-tunnel>
npm run worker                                  # terminal 1
npm run server                                  # terminal 2
curl -X POST localhost:3000/payout -d '{"amount":250,"currency":"EUR","beneficiary":{"id":"ben_small"}}'   # paid at once
curl -X POST localhost:3000/payout -d '{"amount":4200,"currency":"EUR","beneficiary":{"id":"ben_big"}}'   # waits for a human
```

Approve the second one in the dashboard or in Slack and the worker logs `PAID 4200 EUR`. Deny it and the workflow
completes with `{"status":"not_approved","reason":"Denied by ..."}`.

## What makes it safe

- **Retries don't double-ask.** `idempotencyKey: <workflowId>-<activityId>` stays the same across Temporal's activity retries, so a retried `requestDecision` gets the original decision.
- **The signal only wakes the workflow.** It then reads the decision from Auditail itself (`resume()`), so a forged signal can't release a payout, and the callback is HMAC-verified anyway.
- **The receipt travels with the payment.** Have your payout service call `checkReceipt()` before paying.
- **Fails closed.** If Auditail can't be reached, `guard()` returns not-approved; `readDecision` throws and Temporal retries it.

We ran this end to end against an Auditail server with `temporal server start-dev` (Temporal CLI 1.10, TypeScript SDK 1.26): the $250 payout was paid at once, the $4,200 one was paid after approval, and a denied $9,000 one completed as `not_approved`.

More: [Pause and resume](https://auditail.io/docs/guides/agent-runtime#pause-and-resume).
