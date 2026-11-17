# Durable human approval for agent payouts (Inngest + Auditail)

An agent asks for a payout. Small ones are allowed by your policy at once. Large ones wait for a person, for minutes
or hours, **without a process waiting**: the Inngest workflow sleeps on `step.waitForEvent`, and Auditail's signed
callback wakes it when someone approves or denies in the dashboard or in Slack.

```
agent -> app/payout.requested -> [ask-auditail] --allowed--> [pay] -> [report-outcome]
                                       |
                                    pending
                                       v
                            [wait-for-human]  <-- auditail/approval.decided <-- /auditail/callback <-- Auditail (signed)
                                       v
                                [read-decision] --approved--> [pay] -> [report-outcome]
                                                --denied----> stop
```

## Run it

1. Create a free account at [app.auditail.io](https://app.auditail.io). Sign in with the approver token, paste [`policy.json`](./policy.json) into **Policy** and save.
2. Create the callback signing secret once (approver token): `curl -X PUT https://api.auditail.io/v1/settings -H "Authorization: Bearer $AUDITAIL_APPROVER_TOKEN" -H "Content-Type: application/json" -d '{"rotateSecret": true}'` and keep `signingSecret`.
3. Callbacks must reach you over public HTTPS. Locally, use a tunnel (for example `cloudflared tunnel --url http://localhost:3000`).
4. Start Inngest's dev server and this app:

```bash
npm install
npx inngest-cli@latest dev -u http://localhost:3000/api/inngest
INNGEST_DEV=1 AUDITAIL_API_KEY=atl_live_... AUDITAIL_WEBHOOK_SECRET=... PUBLIC_URL=https://<your-tunnel> npm start
```

5. Ask for payouts:

```bash
curl -X POST localhost:3000/payout -d '{"amount":250,"currency":"EUR","beneficiary":{"id":"ben_small"}}'   # paid at once
curl -X POST localhost:3000/payout -d '{"amount":4200,"currency":"EUR","beneficiary":{"id":"ben_big"}}'   # waits for a human
```

Approve the second one in the dashboard. The workflow wakes, reads the decision with `resume()`, and pays with the
signed receipt. Deny it and the workflow stops without paying. Nobody answers in 24 hours: it stops too.

## What makes it safe

- **Retries don't double-pay or double-ask.** `idempotencyKey: payout-<event id>` means Inngest's step retries get the original decision back, not a second approval.
- **The callback is verified** (HMAC-SHA256 over `timestamp.body`, 5-minute window) before it wakes anything. The workflow then reads the decision from Auditail itself (`resume()`), so a forged event alone can't release a payout.
- **The receipt travels with the payment.** Have your payout service call `checkReceipt()` before paying, so a payout that skipped this workflow is refused.
- **Fails closed.** If Auditail can't be reached, `guard()` returns not-approved and nothing is paid.

We ran this end to end against an Auditail server with Inngest's dev server (inngest 4.26): the $250 payout was paid at
once, the $4,200 one waited, and was paid after the approval callback woke the workflow.

More: [Pause and resume](https://auditail.io/docs/guides/agent-runtime#pause-and-resume).
