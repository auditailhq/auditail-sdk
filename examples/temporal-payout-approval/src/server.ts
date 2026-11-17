// Starts payout workflows, and turns Auditail's signed callback into a Temporal signal.
import http from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { Client, Connection } from '@temporalio/client';
import { approvalDecided, payoutWorkflow } from './workflows';

const client = new Client({ connection: await Connection.connect({ address: process.env.TEMPORAL_ADDRESS ?? 'localhost:7233' }) });
const body = (req: http.IncomingMessage) => new Promise<string>((r) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => r(b)); });

function verified(raw: string, ts: string, sig: string): boolean {
  const expected = 'sha256=' + createHmac('sha256', process.env.AUDITAIL_WEBHOOK_SECRET ?? '').update(`${ts}.${raw}`).digest('hex');
  return Math.abs(Date.now() / 1000 - Number(ts)) < 300 && sig.length === expected.length && timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

http.createServer(async (req, res) => {
  try {
    if (req.url === '/payout' && req.method === 'POST') {
      const payout = JSON.parse(await body(req));
      const h = await client.workflow.start(payoutWorkflow, { taskQueue: 'payouts', workflowId: `payout-${Date.now()}`, args: [payout] });
      res.writeHead(202, { 'content-type': 'application/json' }).end(JSON.stringify({ workflowId: h.workflowId }));
      return;
    }
    if (req.url === '/auditail/callback' && req.method === 'POST') {
      const raw = await body(req);
      if (!verified(raw, String(req.headers['x-auditail-timestamp'] ?? ''), String(req.headers['x-auditail-signature'] ?? ''))) { res.writeHead(401).end('bad signature'); return; }
      const msg = JSON.parse(raw);
      await client.workflow.getHandle(msg.correlationId).signal(approvalDecided, msg.approval.id);
      res.writeHead(200).end('ok');
      return;
    }
    res.writeHead(404).end();
  } catch (e) { res.writeHead(500).end(String(e)); }
}).listen(Number(process.env.PORT ?? 3000), () => console.log(`listening on :${process.env.PORT ?? 3000}`));
