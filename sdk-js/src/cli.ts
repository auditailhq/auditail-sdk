#!/usr/bin/env node
/**
 * auditail-verify: check an Auditail evidence export offline.
 *
 *   npx -p auditail-sdk auditail-verify evidence.json [--checkpoint atc1...]... [--account key_...] [--keys keys.json]
 *
 * Exit code 0 = valid, 1 = problems found, 2 = usage error.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { extractPackReports, verifyBundle, verifyEvidence, verifyReport, type PublicKeyInfo } from './verify';

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const held: string[] = [];
  let file: string | undefined, account: string | undefined, keysFile: string | undefined, tokenOut: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--checkpoint') held.push(args[++i]);
    else if (a === '--checkpoints-file') held.push(...readFileSync(args[++i], 'utf8').split(/\s+/).filter((s) => s.startsWith('atc1.')));
    else if (a === '--account') account = args[++i];
    else if (a === '--keys') keysFile = args[++i];
    else if (a === '--write-timestamp') tokenOut = args[++i];
    else if (a === '-h' || a === '--help') file = undefined, i = args.length;
    else if (!file) file = a;
  }
  if (!file) {
    console.error('Usage: auditail-verify <evidence.json> [--checkpoint <atc1...>]... [--checkpoints-file <file>] [--account <key_...>] [--keys <keys.json>] [--write-timestamp <token.der>]\n  <file> is an evidence export, an examiner or reconciliation report, or a decision bundle (GET /v1/evidence/{id}).');
    return 2;
  }
  const raw = readFileSync(file, 'utf8');
  if (/^\s*<!doctype html/i.test(raw)) {
    // A risk pack: verify every signed report inside it.
    const docs = extractPackReports(raw);
    const ids = Object.keys(docs);
    if (!ids.length) { console.log('No signed Auditail reports found in this HTML file.'); return 1; }
    const keys: PublicKeyInfo[] | undefined = keysFile ? JSON.parse(readFileSync(keysFile, 'utf8')).keys : undefined;
    let bad = 0;
    for (const id of ids) {
      const r = await verifyReport(docs[id], { account, publicKeys: keys });
      console.log(`  ${r.valid ? 'ok     ' : 'INVALID'} ${id.replace('auditail-', '')} (${docs[id].account}, ${(docs[id].period as { from?: string })?.from?.slice(0, 10)} to ${(docs[id].period as { to?: string })?.to?.slice(0, 10)})${r.valid ? '' : `: ${r.reason}`}`);
      if (!r.valid) bad++;
    }
    console.log(bad ? `\nINVALID: ${bad} report(s) failed.` : '\nVALID: every report in this pack is signed by Auditail and unchanged. (The printed text is a summary of them.)');
    return bad ? 1 : 0;
  }
  const evidence = JSON.parse(raw);
  const publicKeys: PublicKeyInfo[] | undefined = keysFile ? JSON.parse(readFileSync(keysFile, 'utf8')).keys : undefined;
  if (evidence?.format === 'auditail-decision-bundle-v1') {
    const r = await verifyBundle(evidence, { account, publicKeys });
    console.log(`Decision bundle for ${r.subject} (${evidence.summary?.action}, ${evidence.summary?.outcome}) in ${r.account}`);
    for (const c of r.checks) console.log(`  ok    ${c}`);
    for (const n of r.notes) console.log(`  note  ${n}`);
    const ts = evidence.chain?.timestamp;
    if (tokenOut && ts?.token) { writeFileSync(tokenOut, Buffer.from(ts.token, 'base64')); console.log(`\nWrote the RFC 3161 token to ${tokenOut}:\n  openssl ts -verify -digest ${ts.imprint} -in ${tokenOut} -token_in -CAfile <TSA certificate chain>`); }
    if (r.valid) { console.log('\nVALID: every check above passed.'); return 0; }
    console.log('\nINVALID:'); for (const p of r.problems) console.log(`  - ${p}`); return 1;
  }
  if (evidence?.format === 'auditail-examiner-report-v1' || evidence?.format === 'auditail-reconciliation-report-v1' || evidence?.format === 'auditail-shadow-report-v1') {
    const rep = await verifyReport(evidence, { account, publicKeys });
    console.log(`${evidence.format === 'auditail-examiner-report-v1' ? 'Examiner' : evidence.format === 'auditail-shadow-report-v1' ? 'Shadow' : 'Reconciliation'} report for ${evidence.account}, ${evidence.period?.from} to ${evidence.period?.to}`);
    if (rep.valid) { console.log('\nVALID: signed by Auditail and unchanged since it was generated.'); return 0; }
    console.log(`\nINVALID: ${rep.reason}`); return 1;
  }
  const r = await verifyEvidence(evidence, { account, heldCheckpoints: held, publicKeys });
  console.log(`Account:   ${r.account}`);
  console.log(`Events:    ${r.checked}${r.firstSeq !== null ? ` (#${r.firstSeq} to #${r.lastSeq})` : ''}`);
  console.log(`Keys:      ${keysFile ? `pinned from ${keysFile}` : 'fetched from api.auditail.io'}`);
  if (held.length) console.log(`Held checkpoints matched: ${r.matchedCheckpoints} of ${held.length}`);
  for (const n of r.notes) console.log(`Note:      ${n}`);
  if (r.valid) { console.log('\nVALID: every event is intact, linked in order, and vouched for by an Auditail signature.'); return 0; }
  console.log('\nINVALID:');
  for (const p of r.problems) console.log(`  - ${p}`);
  return 1;
}

main().then((code) => process.exit(code), (e) => { console.error(`auditail-verify: ${(e as Error).message}`); process.exit(2); });
