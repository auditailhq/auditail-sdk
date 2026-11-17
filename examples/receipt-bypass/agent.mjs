// Three agents call the payout service. Only the one that went through guard() gets paid, once.
import { Auditail } from 'auditail-sdk';

const auditail = new Auditail({ apiKey: process.env.AUDITAIL_API_KEY, serverPolicy: true, logLevel: 'silent',
  ...(process.env.AUDITAIL_BASE_URL ? { baseUrl: process.env.AUDITAIL_BASE_URL } : {}) });
const pay = (body) => fetch('http://localhost:4100/payout', { method: 'POST', body: JSON.stringify(body) }).then((r) => r.json());
const payout = { amount: 900, currency: 'USD', beneficiary: { id: 'ben_acme' } };

console.log('1. An agent that skips guard() (a prompt told it the check is "only for testing"):');
console.log('  ', await pay({ payout }));

console.log('2. An agent that goes through guard():');
const r = await auditail.guard({ action: 'create_payout', payload: payout, agentId: 'payout-agent' });
console.log('  ', await pay({ payout, receipt: r.receipt, requestId: 'run-1' }));

console.log('3. The same receipt again, and the receipt with a different amount or beneficiary:');
console.log('  ', await pay({ payout, receipt: r.receipt, requestId: 'run-2' }));
console.log('  ', await pay({ payout: { ...payout, amount: 9000 }, receipt: r.receipt, requestId: 'run-3' }));
console.log('  ', await pay({ payout: { ...payout, beneficiary: { id: 'ben_attacker' } }, receipt: r.receipt, requestId: 'run-4' }));
