# Guarded tools for the Vercel AI SDK

Every money-moving tool asks Auditail before it runs. Allowed calls go through with a signed receipt for your
payment client. Calls that need a person, or that the policy refuses, return a plain explanation **to the model**,
so it tells the user instead of retrying.

```bash
npm install
AUDITAIL_API_KEY=atl_live_... node agent.mjs                 # scripted mock model, no LLM key needed
AUDITAIL_API_KEY=atl_live_... OPENAI_API_KEY=sk-... node agent.mjs "Refund order 4471 ($48) and order 9120 ($640)"
```

Paste [`policy.json`](./policy.json) into **Policy** first (refunds over $200 need a human).

```
[payments] REFUNDED 48 USD for 4471 (receipt atr1....)
tool issue_refund({"orderId":"4471","amount":48,...}) -> {"status":"refunded",...}
tool issue_refund({"orderId":"9120","amount":640,...}) -> {"status":"waiting_for_approval","approvalId":"apr_...","message":"Not done yet: a person must approve this (...). Tell the user."}

assistant: Order 4471 is refunded. The $640 refund for order 9120 needs a person to approve it first; I will let you know.
```

## The pattern

```javascript
function guarded(action, execute) {
  return async (input) => {
    const r = await auditail.guard({ action, payload: input, agentId: 'support-agent', sessionId, wait: false });
    if (r.approved) return execute(input, r.receipt);           // pass the receipt to your payment client
    if (r.pending) return { status: 'waiting_for_approval', approvalId: r.approval.id, message: '... Tell the user.' };
    return { status: 'not_allowed', code: r.code, message: `${r.reason} Do not retry; tell the user.` };
  };
}
```

- `wait: false` keeps a chat request from hanging while a person decides. Pick it up later with `resume(approvalId)`, or a [signed callback](https://auditail.io/docs/guides/agent-runtime#pause-and-resume).
- `sessionId` ties the conversation together, so a refund after the model read an email or a web page needs a person ([session taint](https://auditail.io/docs/guides/agent-runtime#session-taint-after-untrusted-content)). Mark untrusted reads with `auditail.markUntrusted(sessionId, 'web_page')` in the tools that fetch content.
- If Auditail can't be reached, `guard()` returns not-approved, and the tool doesn't run.

Tested with `ai` 7.0 using the SDK's `MockLanguageModelV4`, which makes the same tool calls a real model would. The `OPENAI_API_KEY` path uses `@ai-sdk/openai` the standard way; we haven't run it in this example's tests.
