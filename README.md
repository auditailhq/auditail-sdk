# Auditail SDKs and verifier

> **Controls and evidence for AI agents that move money.**
> Limits agents can't change, human approval for risky actions, a kill switch, settlement checks, and a signed, tamper-evident record of every decision.

**[📖 Documentation](https://auditail.io/docs)** · **[🧭 For evaluators](https://auditail.io/docs/evaluators)** · **[📝 Changelog](https://auditail.io/docs/changelog)** · **[Sample risk pack](https://auditail.io/samples/auditail-sample-risk-pack.html)**

This repository holds everything that runs on your side, under the MIT license:

| Path | What it is |
|---|---|
| [`sdk-js`](./sdk-js) | `auditail-sdk` on npm: `guard()`, receipts, the MCP proxy (`auditail-mcp-proxy`) and the offline verifier (`auditail-verify`) |
| [`sdk-python`](./sdk-python) | `auditail` on PyPI: `guard()`, receipts and receipt verification |
| [`examples`](./examples) | Runnable examples: a prompt-injected refund stopped over MCP; durable payout approval with Inngest |
| [`AUDITAIL_PUBLIC_KEYS.json`](./AUDITAIL_PUBLIC_KEYS.json) | Auditail's Ed25519 public keys, pinned |

The Auditail service (policy engine, approvals, settlement, reports, dashboard) is proprietary and runs at api.auditail.io.

## You don't have to trust us

Everything Auditail signs can be checked with the open-source verifier here, offline, without access to our servers or code:

- **Receipts** bind an approval or policy decision to your account, the action and the exact payload (`verifyReceipt`, `checkReceipt`).
- **Evidence exports** recompute every hash in your log and check signed checkpoints you saved (`auditail-verify export.json`).
- **Decision bundles** check one payment end to end: receipt, policy text, approvers' own Ed25519 signatures, outcomes and the log segment (`auditail-verify bundle.json`).
- **Independent RFC 3161 timestamps** from a public timestamp authority, checkable with OpenSSL.
- **Reports and risk packs** are signed and verify the same way.

## Install

```bash
npm install auditail-sdk   # JavaScript / TypeScript
pip install auditail        # Python
```

```typescript
import { Auditail } from 'auditail-sdk';

const auditail = new Auditail({ apiKey: process.env.AUDITAIL_API_KEY!, serverPolicy: true });
const payout = { amount: 9999, beneficiary: { id: 'ben_7' } };
const r = await auditail.guard({ action: 'create_payout', payload: payout, agentId: 'payout-agent' });
if (r.approved) await payments.createPayout(payout, { auditailReceipt: r.receipt }); // your payment client
else console.log(r.code, r.reason);
```

Start with the [quickstart](https://auditail.io/docs/quickstart). Questions or an account: hello@auditail.io.

## Security

See [SECURITY.md](./SECURITY.md).
