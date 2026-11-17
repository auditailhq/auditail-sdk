// The payout service: the only thing that holds the payment credentials. It pays only with a valid, unused
// Auditail receipt for exactly this payload. Agents can't skip guard(), because without a receipt nothing is paid.
import http from 'node:http';
import { Auditail } from 'auditail-sdk';

// A service credential for the payout service (an approver token or a full-access key of the same account).
const auditail = new Auditail({ apiKey: process.env.AUDITAIL_SERVICE_KEY, logLevel: 'silent',
  ...(process.env.AUDITAIL_BASE_URL ? { baseUrl: process.env.AUDITAIL_BASE_URL } : {}) });

http.createServer((req, res) => {
  let b = ''; req.on('data', (c) => (b += c)); req.on('end', async () => {
    const { payout, receipt, requestId } = JSON.parse(b || '{}');
    const check = await auditail.checkReceipt(receipt, { action: 'create_payout', payload: payout, requestId });
    if (!check.ok) {
      console.log(`[payout-service] REFUSED ${payout?.amount} to ${payout?.beneficiary?.id}: ${check.code} (${check.reason})`);
      res.writeHead(403, { 'content-type': 'application/json' }).end(JSON.stringify({ paid: false, code: check.code, reason: check.reason }));
      return;
    }
    console.log(`[payout-service] PAID ${payout.amount} ${payout.currency} to ${payout.beneficiary.id} (approved ${check.claims.typ === 'approval' ? 'by ' + check.claims.dby : 'by policy'})`);
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ paid: true, paymentId: `po_${Date.now()}` }));
  });
}).listen(4100, () => console.log('[payout-service] listening on :4100'));
