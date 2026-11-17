// Durable human approval for agent payouts with Inngest and Auditail.
//
//   1. The workflow asks Auditail (guard, wait: false). Small payouts are allowed at once, with a signed receipt.
//   2. Large ones open an approval. The workflow sleeps on step.waitForEvent: no process holds a connection open.
//   3. When a human decides (dashboard or Slack), Auditail POSTs a signed callback to /auditail/callback.
//      This server checks the signature and sends an Inngest event, which wakes the workflow.
//   4. The workflow calls resume() to read the final decision and the receipt, then pays (or doesn't).
//
// Run:  npx inngest-cli@latest dev -u http://localhost:3000/api/inngest      (Inngest dev server)
//       AUDITAIL_API_KEY=... AUDITAIL_WEBHOOK_SECRET=... PUBLIC_URL=https://<tunnel> node server.mjs
import http from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { Inngest } from 'inngest';
import { serve } from 'inngest/node';
import { Auditail } from 'auditail-sdk';

const inngest = new Inngest({ id: 'payouts-demo' });
const auditail = new Auditail({ apiKey: process.env.AUDITAIL_API_KEY, serverPolicy: true, logLevel: 'warn',
  ...(process.env.AUDITAIL_BASE_URL ? { baseUrl: process.env.AUDITAIL_BASE_URL } : {}) });
const CALLBACK_URL = `${process.env.PUBLIC_URL ?? 'http://localhost:3000'}/auditail/callback`;

/** Your payment client. Pass the receipt so the payout service can check it (checkReceipt) before paying. */
async function executePayout(payout, receipt) {
  console.log(`[payouts] PAID ${payout.amount} ${payout.currency} to ${payout.beneficiary.id} (receipt ${receipt.slice(0, 18)}...)`);
  return { paymentId: `po_${Date.now()}` };
}

const payout = inngest.createFunction(
  { id: 'agent-payout', triggers: [{ event: 'app/payout.requested' }] },
  async ({ event, step }) => {
    const p = event.data.payout;
    const decision = await step.run('ask-auditail', async () => {
      const r = await auditail.guard({
        action: 'create_payout', payload: p, agentId: event.data.agentId ?? 'payout-agent', wait: false,
        correlationId: event.id, callbackUrl: CALLBACK_URL,
        idempotencyKey: `payout-${event.id}`, // Inngest retries this step: the same key returns the same decision
      });
      return { approved: r.approved, pending: r.pending, approvalId: r.approval?.id ?? null, receipt: r.receipt ?? null, code: r.code, reason: r.reason };
    });

    let receipt = decision.receipt;
    if (!decision.approved) {
      if (!decision.pending) return { status: 'blocked', code: decision.code, reason: decision.reason };
      // Sleep until Auditail's callback arrives (or a day passes).
      const woke = await step.waitForEvent('wait-for-human', {
        event: 'auditail/approval.decided', timeout: '24h', if: `async.data.approvalId == "${decision.approvalId}"`,
      });
      const final = await step.run('read-decision', () => auditail.resume(decision.approvalId));
      if (!final.approved) return { status: 'not_approved', woke: !!woke, code: final.code, reason: final.reason };
      receipt = final.receipt;
    }
    const paid = await step.run('pay', () => executePayout(p, receipt));
    // Record what happened. From an agent key this is recorded only; your payment provider's events or an approver
    // token make it a trusted settlement report (see "Settlement and evidence" in the docs).
    await step.run('report-outcome', () => auditail.reportOutcome({ receipt }, { status: 'settled', externalTxId: paid.paymentId }));
    return { status: 'paid', ...paid };
  },
);

/** Auditail's signed callback: verify, then wake the workflow. */
async function callback(req, res) {
  const body = await new Promise((r) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => r(b)); });
  const ts = req.headers['x-auditail-timestamp'] ?? '';
  const expected = 'sha256=' + createHmac('sha256', process.env.AUDITAIL_WEBHOOK_SECRET ?? '').update(`${ts}.${body}`).digest('hex');
  const got = String(req.headers['x-auditail-signature'] ?? '');
  const fresh = Math.abs(Date.now() / 1000 - Number(ts)) < 300;
  if (!fresh || got.length !== expected.length || !timingSafeEqual(Buffer.from(got), Buffer.from(expected))) { res.writeHead(401).end('bad signature'); return; }
  const msg = JSON.parse(body);
  await inngest.send({ name: 'auditail/approval.decided', data: { approvalId: msg.approval.id, status: msg.approval.status, correlationId: msg.correlationId } });
  res.writeHead(200).end('ok');
}

const inngestHandler = serve({ client: inngest, functions: [payout] });
http.createServer((req, res) => {
  if (req.url === '/auditail/callback' && req.method === 'POST') return void callback(req, res);
  if (req.url?.startsWith('/api/inngest')) return inngestHandler(req, res);
  if (req.url === '/payout' && req.method === 'POST') {
    // Demo entry point: an agent asks for a payout.
    let b = ''; req.on('data', (c) => (b += c)); req.on('end', async () => {
      const { ids } = await inngest.send({ name: 'app/payout.requested', data: { payout: JSON.parse(b), agentId: 'payout-agent' } });
      res.writeHead(202, { 'content-type': 'application/json' }).end(JSON.stringify({ eventId: ids[0] }));
    });
    return;
  }
  res.writeHead(404).end();
}).listen(Number(process.env.PORT ?? 3000), () => console.log(`listening on :${process.env.PORT ?? 3000}; Auditail callbacks go to ${CALLBACK_URL}`));
