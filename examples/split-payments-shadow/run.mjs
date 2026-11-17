// An AP agent pays a $14,700 invoice as three payouts just under the $5,000 approval threshold, to a vendor it has
// never paid before. A per-payment rule ("> $5,000 needs a human") sees nothing wrong with any single one.
// In shadow mode Auditail blocks nothing, and the shadow drift report shows the pattern.
//
//   AUDITAIL_API_KEY=atl_live_... AUDITAIL_APPROVER_TOKEN=atl_appr_... node run.mjs
import { writeFileSync } from 'node:fs';
import { Auditail } from 'auditail-sdk';

const BASE = process.env.AUDITAIL_BASE_URL ?? 'https://api.auditail.io';
const { AUDITAIL_API_KEY: KEY, AUDITAIL_APPROVER_TOKEN: APPROVER } = process.env;
if (!KEY || !APPROVER) { console.error('Set AUDITAIL_API_KEY (agent key) and AUDITAIL_APPROVER_TOKEN (to read the report). Use a test account: run.mjs replaces its policy.'); process.exit(2); }
const api = async (path, init = {}) => { const r = await fetch(BASE + path, { ...init, headers: { authorization: `Bearer ${APPROVER}`, 'content-type': 'application/json', ...init.headers } }); if (!r.ok) throw new Error(`${path}: HTTP ${r.status} ${await r.text()}`); return r; };

// 1. Shadow-mode policy (see policy.json): nothing is blocked, everything is recorded.
await api('/v1/policy', { method: 'PUT', body: (await import('node:fs')).readFileSync(new URL('./policy.json', import.meta.url)) });

// 2. The agent's payouts, as your payment tool would guard them.
const auditail = new Auditail({ apiKey: KEY, baseUrl: BASE, serverPolicy: true, logLevel: 'silent' });
const pay = async (amount, beneficiary, note) => {
  const r = await auditail.guard({ action: 'create_payout', payload: { amount, currency: 'USD', beneficiary: { id: beneficiary } }, agentId: 'ap-agent' });
  console.log(`payout ${String(amount).padStart(5)} USD to ${beneficiary.padEnd(18)} ${r.approved ? 'allowed' : 'blocked'}${r.shadow && r.shadow.wouldBe !== 'allow' ? `  (enforced, this would be: ${r.shadow.wouldBe}, ${r.shadow.code})` : ''}  ${note}`);
};
await pay(1200, 'ben_acme', 'routine');
await pay(3400, 'ben_northwind', 'routine');
await pay(4900, 'ben_new_vendor_77', 'invoice INV-8812, part 1');
await pay(4850, 'ben_new_vendor_77', 'invoice INV-8812, part 2');
await pay(4950, 'ben_new_vendor_77', 'invoice INV-8812, part 3');

// 3. The shadow drift report: what a risk team asks about first.
const report = await (await api('/v1/report/shadow')).json();
console.log('\nShadow drift report:');
for (const line of report.summary) console.log(`  - ${line}`);
for (const s of report.drift.possibleSplits) console.log(`  * ${s.count} x ${s.action} to ${s.recipientField}=${s.recipient}: ${s.total} total, threshold ${s.threshold}`);

// 4. The file you hand to risk, finance or your sponsor bank.
writeFileSync('risk-pack.html', await (await api('/v1/report/pack')).text());
console.log('\nWrote risk-pack.html. Open it and print to PDF; check it with: npx -p auditail-sdk auditail-verify risk-pack.html');
