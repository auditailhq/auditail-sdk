# Human approval for agent payouts (LangGraph + Auditail)

A LangGraph node asks Auditail before paying. Small payouts go through. Large ones **pause the graph** with
`interrupt()`; once a person approves or denies in the Auditail dashboard (or Slack), the graph resumes on the same
thread with `Command(resume=approval_id)`.

```bash
pip install -r requirements.txt
AUDITAIL_API_KEY=atl_live_... python payout_graph.py 250    # paid at once
AUDITAIL_API_KEY=atl_live_... python payout_graph.py 4200   # pauses until a human decides
```

Paste [`policy.json`](./policy.json) into **Policy** first (payouts over $1,000 need a human).

```
Paused: Needs approval: payouts over $1,000 need a human. Awaiting a human (apr_...); not approved yet.
Approve or deny apr_... in the Auditail dashboard (or Slack)...
[payouts] PAID 4200.0 EUR to ben_big (receipt atr1....)
Result: paid
```

## Details that matter

- **The node runs twice.** LangGraph re-runs an interrupted node from the top on resume. `idempotency_key=f"{thread_id}-pay"` makes the second `guard()` return the original decision, so one payout opens one approval (we checked: exactly one).
- **Resume from the callback in production.** This script polls `resume()` so it runs without a public URL. In a server, set `callback_url` and `correlation_id=thread_id` on `guard()`, verify the signed callback, and call `app.invoke(Command(resume=approval_id), {"configurable": {"thread_id": correlation_id}})`.
- **Use a durable checkpointer** (Postgres, Redis, SQLite) instead of `InMemorySaver`, so a paused graph survives a restart.
- **The receipt travels with the payment:** have the payout service call `check_receipt()` before paying.

Tested with LangGraph 1.2 and the `auditail` Python SDK 0.11.

More: [Pause and resume](https://auditail.io/docs/guides/agent-runtime#langgraph).
