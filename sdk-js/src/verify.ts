import { b64urlDecode, canonicalJson, ed25519Verify, redact, redactSet, sha256Hex } from './shared';

export const DEFAULT_KEYS_URL = 'https://api.auditail.io/.well-known/auditail-keys.json';
const GENESIS = '0'.repeat(64);
const enc = new TextEncoder();
const dec = new TextDecoder();

export interface PublicKeyInfo { kid: string; alg: 'Ed25519'; publicKey: string; status?: string }

export interface ReceiptClaims {
  v: 1;
  /** 'approval' = a human approved it; 'decision' = your server-side policy allowed it. */
  typ: 'approval' | 'decision';
  kid: string;
  /** 'policy' on decision receipts. */
  by?: 'policy';
  /** Policy version that allowed it (decision receipts). */
  pv?: number;
  /** Your Auditail account id (key_...). */
  acct: string;
  /** Approval id. Record it to make each receipt single-use. */
  aid: string;
  agent: string; act: string; env: string;
  /** sha256 of the canonical JSON of the payload as the approver saw it (secret fields redacted). */
  ph: string;
  dby: string | null;
  iat: number; exp: number;
  /** Agent session id, and whether it had read untrusted data (1) when this was authorized. */
  sid?: string; tnt?: 0 | 1;
  /** Number of approvers who signed the approval with their own key. */
  asig?: number;
}

export interface CheckpointClaims { v: 1; typ: 'checkpoint'; kid: string; acct: string; seq: number; hash: string; iat: number }

export type VerifyResult<C> = { valid: true; claims: C } | { valid: false; reason: string; claims?: C };

// ---------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------

let keyCache: { url: string; at: number; keys: PublicKeyInfo[] } | null = null;

/** Fetches Auditail's public keys (cached 5 minutes). For the strongest guarantee, pin them with `publicKeys`. */
export async function fetchPublicKeys(url = DEFAULT_KEYS_URL): Promise<PublicKeyInfo[]> {
  if (keyCache && keyCache.url === url && Date.now() - keyCache.at < 300_000) return keyCache.keys;
  const res = await fetch(url, { headers: { 'user-agent': 'auditail-verify/1' } });
  if (!res.ok) throw new Error(`Could not fetch Auditail public keys (HTTP ${res.status})`);
  const body = (await res.json()) as { keys?: PublicKeyInfo[] };
  const keys = (body.keys ?? []).filter((k) => k.alg === 'Ed25519' && typeof k.publicKey === 'string' && typeof k.kid === 'string');
  keyCache = { url, at: Date.now(), keys };
  return keys;
}

async function verifyToken<C extends { kid: string }>(token: string, prefix: string, keys: PublicKeyInfo[]): Promise<VerifyResult<C>> {
  if (typeof token !== 'string') return { valid: false, reason: 'not a token' };
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== prefix) return { valid: false, reason: `malformed: expected ${prefix}.<claims>.<signature>` };
  let claims: C;
  try { claims = JSON.parse(dec.decode(b64urlDecode(parts[1]))) as C; } catch { return { valid: false, reason: 'malformed claims' }; }
  const key = keys.find((k) => k.kid === claims.kid);
  if (!key) return { valid: false, reason: `unknown signing key ${String(claims.kid)}`, claims };
  let ok = false;
  try { ok = await ed25519Verify(key.publicKey, b64urlDecode(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`)); } catch { ok = false; }
  if (!ok) return { valid: false, reason: 'bad signature (token was altered or not issued by Auditail)', claims };
  return { valid: true, claims };
}

// ---------------------------------------------------------------------------
// receipts
// ---------------------------------------------------------------------------

export interface VerifyReceiptOptions {
  /** Required. Your Auditail account id (key_...). Rejects receipts issued to any other Auditail customer. */
  account: string;
  /** The action you are about to execute. Strongly recommended. */
  action?: string;
  /** The payload you are about to execute. Strongly recommended: it is hashed and compared with the approved one. */
  payload?: Record<string, unknown>;
  agentId?: string;
  environment?: string;
  /** Extra redaction keys, if the agent's client was configured with `redactKeys`. */
  redactKeys?: string[];
  /** Pin keys instead of fetching them. */
  publicKeys?: PublicKeyInfo[];
  keysUrl?: string;
  /** Clock skew tolerance in seconds. Default 60. */
  clockSkewSeconds?: number;
  /** Override the current time (ms since epoch). For tests. */
  now?: number;
  /**
   * Accept only receipts for actions a human approved. Use this where a policy decision alone is not enough.
   * Default false: receipts from your server-side policy (typ "decision") are accepted too.
   */
  requireHumanApproval?: boolean;
}

/**
 * Verifies an approval receipt before executing a high-risk action. Returns { valid: false, reason } rather than
 * throwing. A valid result proves Auditail recorded a human approving exactly this action and payload.
 * You must still make each receipt single-use: store `claims.aid` and reject receipts you have already seen.
 */
export async function verifyReceipt(receipt: string, opts: VerifyReceiptOptions): Promise<VerifyResult<ReceiptClaims>> {
  if (!opts || typeof opts.account !== 'string' || !opts.account) return { valid: false, reason: 'options.account is required' };
  let keys: PublicKeyInfo[];
  try { keys = opts.publicKeys ?? (await fetchPublicKeys(opts.keysUrl)); } catch (e) { return { valid: false, reason: (e as Error).message }; }
  const r = await verifyToken<ReceiptClaims>(receipt, 'atr1', keys);
  if (!r.valid) return r;
  const c = r.claims;
  const fail = (reason: string): VerifyResult<ReceiptClaims> => ({ valid: false, reason, claims: c });
  if (c.v !== 1 || (c.typ !== 'approval' && c.typ !== 'decision')) return fail('not an Auditail receipt');
  if (opts.requireHumanApproval && c.typ !== 'approval') return fail('a human approval is required, but this receipt is a policy decision');
  if (c.acct !== opts.account) return fail('receipt belongs to a different Auditail account');
  if (opts.action !== undefined && c.act !== opts.action) return fail(`receipt is for action "${c.act}", not "${opts.action}"`);
  if (opts.agentId !== undefined && c.agent !== opts.agentId) return fail(`receipt is for agent "${c.agent}", not "${opts.agentId}"`);
  if (opts.environment !== undefined && c.env !== opts.environment) return fail(`receipt is for environment "${c.env}", not "${opts.environment}"`);
  const now = Math.floor((opts.now ?? Date.now()) / 1000);
  const skew = opts.clockSkewSeconds ?? 60;
  if (now > c.exp + skew) return fail('receipt has expired');
  if (c.iat > now + skew) return fail('receipt is not valid yet');
  if (opts.payload !== undefined) {
    const ph = await sha256Hex(canonicalJson(redact(opts.payload, redactSet(opts.redactKeys))));
    if (ph !== c.ph) return fail('payload does not match the approved payload');
  }
  return { valid: true, claims: c };
}

export async function verifyCheckpoint(checkpoint: string, opts: { account?: string; publicKeys?: PublicKeyInfo[]; keysUrl?: string } = {}): Promise<VerifyResult<CheckpointClaims>> {
  let keys: PublicKeyInfo[];
  try { keys = opts.publicKeys ?? (await fetchPublicKeys(opts.keysUrl)); } catch (e) { return { valid: false, reason: (e as Error).message }; }
  const r = await verifyToken<CheckpointClaims>(checkpoint, 'atc1', keys);
  if (!r.valid) return r;
  if (r.claims.v !== 1 || r.claims.typ !== 'checkpoint') return { valid: false, reason: 'not a checkpoint', claims: r.claims };
  if (opts.account !== undefined && r.claims.acct !== opts.account) return { valid: false, reason: 'checkpoint belongs to a different account', claims: r.claims };
  return r;
}

// ---------------------------------------------------------------------------
// evidence exports
// ---------------------------------------------------------------------------

export interface EvidenceEvent {
  seq: number; audit_id: string; agent_id: string; user_id: string | null; action: string; approved: number;
  reason: string | null; matched_rule: string | null; environment: string; tags_json: string | null; payload_json: string;
  sdk_version?: string | null; event_time: string; received_at: string; prev_hash: string; hash: string;
}
export interface Evidence { format: string; account: string; events: EvidenceEvent[]; checkpoint: string | null; [k: string]: unknown }

export interface EvidenceReport {
  valid: boolean;
  /** Problems found. Empty when valid. */
  problems: string[];
  /** Informational notes, for example a held checkpoint outside the exported range. */
  notes: string[];
  account: string;
  checked: number;
  firstSeq: number | null;
  lastSeq: number | null;
  /** Held checkpoints that matched the export. */
  matchedCheckpoints: number;
}

/** Must match the server's canonical event encoding exactly. */
function eventCanonical(e: EvidenceEvent): string {
  return JSON.stringify([e.seq, e.audit_id, e.agent_id, e.user_id, e.action, e.approved, e.reason, e.matched_rule,
    e.environment, e.tags_json, e.payload_json, e.event_time, e.received_at]);
}

/**
 * Verifies an evidence export offline: every hash, every link, and the signed checkpoint for the last event.
 * Pass checkpoints you saved earlier (from webhooks or /v1/checkpoint) as `heldCheckpoints`: if the log was
 * rewritten after you saved them, even consistently, they will not match.
 */
export async function verifyEvidence(evidence: Evidence, opts: { account?: string; heldCheckpoints?: string[]; publicKeys?: PublicKeyInfo[]; keysUrl?: string } = {}): Promise<EvidenceReport> {
  const problems: string[] = [];
  const notes: string[] = [];
  const events = Array.isArray(evidence?.events) ? evidence.events : [];
  const report = (): EvidenceReport => ({
    valid: problems.length === 0, problems, notes, account: evidence?.account, checked: events.length,
    firstSeq: events[0]?.seq ?? null, lastSeq: events[events.length - 1]?.seq ?? null, matchedCheckpoints,
  });
  let matchedCheckpoints = 0;

  if (evidence?.format !== 'auditail-evidence-v1') { problems.push('unknown evidence format'); return report(); }
  if (opts.account !== undefined && evidence.account !== opts.account) problems.push(`evidence is for account ${evidence.account}, not ${opts.account}`);

  let keys: PublicKeyInfo[];
  try { keys = opts.publicKeys ?? (await fetchPublicKeys(opts.keysUrl)); } catch (e) { problems.push((e as Error).message); return report(); }

  // 1. chain: contiguous sequence, correct links, every hash recomputes
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (i > 0 && e.seq !== events[i - 1].seq + 1) { problems.push(`event #${events[i - 1].seq + 1} is missing`); break; }
    const expectedPrev = i === 0 ? (e.seq === 1 ? GENESIS : e.prev_hash) : events[i - 1].hash;
    if (e.prev_hash !== expectedPrev) { problems.push(`event #${e.seq} is not linked to the previous event`); break; }
    if ((await sha256Hex(e.prev_hash + '\n' + eventCanonical(e))) !== e.hash) { problems.push(`event #${e.seq} was modified (its hash does not match its contents)`); break; }
  }

  // 2. the signed checkpoint must vouch for the last event
  if (!evidence.checkpoint) {
    problems.push('evidence has no signed checkpoint');
  } else {
    const cp = await verifyCheckpoint(evidence.checkpoint, { account: evidence.account, publicKeys: keys });
    if (!cp.valid) problems.push(`checkpoint: ${cp.reason}`);
    else if (events.length) {
      const last = events[events.length - 1];
      if (cp.claims.seq !== last.seq || cp.claims.hash !== last.hash) problems.push('the signed checkpoint does not match the last event (the export was altered)');
    }
  }

  // 2b. independent RFC 3161 timestamps of checkpoints in the export
  const stamps = Array.isArray(evidence.timestamps) ? (evidence.timestamps as TimestampInfo[]) : [];
  let stampsOk = 0;
  for (const ts of stamps) {
    const e = events.find((x) => x.seq === ts.seq);
    const p = e ? await checkTimestamp(evidence.account, e.seq, e.hash, ts) : 'the timestamped event is not in the export';
    if (p) problems.push(`timestamp for event #${ts.seq}: ${p}`); else stampsOk++;
  }
  if (stampsOk) notes.push(`${stampsOk} independent RFC 3161 timestamp(s) match the log (from ${stamps[0].tsa}). Verify the authority's signature with openssl ts -verify; see the docs.`);

  // 3. checkpoints the customer saved earlier: catch a rewrite of the whole chain
  for (const held of opts.heldCheckpoints ?? []) {
    const cp = await verifyCheckpoint(held, { account: evidence.account, publicKeys: keys });
    if (!cp.valid) { problems.push(`held checkpoint: ${cp.reason}`); continue; }
    const e = events.find((x) => x.seq === cp.claims.seq);
    if (!e) {
      // A checkpoint past the end of an export that should include it means events were removed from the end.
      const last = events[events.length - 1];
      const range = evidence.range as { to?: string | null } | undefined;
      const coveredUntil = Date.parse((range?.to ?? (evidence.generatedAt as string | undefined)) ?? '');
      if (last && cp.claims.seq > last.seq && Number.isFinite(coveredUntil) && cp.claims.iat * 1000 <= coveredUntil) {
        problems.push(`the log ends at event #${last.seq}, but you hold a checkpoint for event #${cp.claims.seq} made on ${new Date(cp.claims.iat * 1000).toISOString()}: events were removed from the end of the log`);
      } else notes.push(`held checkpoint for event #${cp.claims.seq} is outside this export's range`);
      continue;
    }
    if (e.hash !== cp.claims.hash) problems.push(`event #${cp.claims.seq} differs from the checkpoint you saved on ${new Date(cp.claims.iat * 1000).toISOString()}: the log was rewritten`);
    else matchedCheckpoints++;
  }
  return report();
}

// ---------------------------------------------------------------------------
// examiner reports
// ---------------------------------------------------------------------------

export interface StatementClaims { v: 1; typ: 'report'; kid: string; acct: string; sha: string; iat: number }

/**
 * Verifies a signed examiner report: the signature is Auditail's, and the report body has not been changed since
 * it was generated. The hash covers every field except `signature` and `publicKeys`.
 */
export const SIGNED_DOCUMENT_FORMATS = ['auditail-examiner-report-v1', 'auditail-reconciliation-report-v1', 'auditail-shadow-report-v1', 'auditail-decision-bundle-v1'];

/**
 * Verifies any signed Auditail document (examiner report, reconciliation report, decision bundle): the signature is
 * Auditail's and nothing changed since it was generated. For decision bundles, verifyBundle() also checks the contents.
 */
export async function verifyReport(report: Record<string, unknown>, opts: { account?: string; publicKeys?: PublicKeyInfo[]; keysUrl?: string } = {}): Promise<VerifyResult<StatementClaims>> {
  if (!report || typeof report !== 'object' || !SIGNED_DOCUMENT_FORMATS.includes(report.format as string)) return { valid: false, reason: 'not a signed Auditail report or bundle' };
  let keys: PublicKeyInfo[];
  try { keys = opts.publicKeys ?? (await fetchPublicKeys(opts.keysUrl)); } catch (e) { return { valid: false, reason: (e as Error).message }; }
  const r = await verifyToken<StatementClaims>(String(report.signature ?? ''), 'ats1', keys);
  if (!r.valid) return r;
  const c = r.claims;
  if (c.v !== 1 || c.typ !== 'report') return { valid: false, reason: 'signature is not for a report', claims: c };
  if (c.acct !== report.account) return { valid: false, reason: 'report account does not match its signature', claims: c };
  if (opts.account !== undefined && c.acct !== opts.account) return { valid: false, reason: `report is for account ${c.acct}, not ${opts.account}`, claims: c };
  const { signature: _s, publicKeys: _k, ...body } = report;
  if ((await sha256Hex(canonicalJson(body))) !== c.sha) return { valid: false, reason: 'the report was changed after Auditail signed it', claims: c };
  return { valid: true, claims: c };
}

/** Signed reports embedded in a risk pack (GET /v1/report/pack), keyed by their element id. */
export function extractPackReports(html: string): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  const re = /<script type="application\/json" id="(auditail-[a-z-]+)">([\s\S]*?)<\/script>/g;
  for (let m = re.exec(html); m; m = re.exec(html)) out[m[1]] = JSON.parse(m[2]);
  return out;
}

// ---------------------------------------------------------------------------
// RFC 3161 timestamps
// ---------------------------------------------------------------------------

export interface TimestampInfo { seq: number; hash: string; imprint: string; tsa: string; genTime: string | null; token: string; createdAt?: string }

/** The string whose SHA-256 a timestamp authority signs for a checkpoint. */
export const timestampImprintInput = (account: string, seq: number, hash: string) => `auditail-checkpoint:v1:${account}:${seq}:${hash}`;

function b64Decode(s: string): Uint8Array {
  if (typeof atob === 'function') return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  return new Uint8Array(Buffer.from(s, 'base64'));
}

/**
 * Checks that a timestamp token covers this event: the imprint is the hash of this account, position and event hash,
 * and the token carries that imprint. Returns a problem, or null. The authority's own signature is checked with
 * standard tools (openssl ts -verify -digest <imprint> -in token.der -token_in -CAfile <chain>).
 */
export async function checkTimestamp(account: string, seq: number, hash: string, ts: TimestampInfo): Promise<string | null> {
  if (ts.hash !== hash) return 'it is for a different event hash (the log was changed after it was timestamped)';
  const imprint = await sha256Hex(timestampImprintInput(account, seq, hash));
  if (imprint !== ts.imprint) return 'its imprint does not match this account, position and hash';
  const digest = Uint8Array.from(imprint.match(/../g)!.map((h) => parseInt(h, 16)));
  const token = b64Decode(ts.token);
  outer: for (let i = 0; i <= token.length - digest.length; i++) {
    for (let j = 0; j < digest.length; j++) if (token[i + j] !== digest[j]) continue outer;
    return null;
  }
  return 'the token does not carry the imprint';
}

// ---------------------------------------------------------------------------
// decision bundles (GET /v1/evidence/{auditId})
// ---------------------------------------------------------------------------

export interface BundleReport { valid: boolean; problems: string[]; notes: string[]; subject?: string; account?: string; checks: string[] }

/** The statement an approver signs with their own key (see "approver signatures" in the docs). */
export const approvalStatement = (account: string, approvalId: string, decision: 'approve' | 'deny', payloadHash: string, signedAt: string) =>
  `auditail-approval:v1:${account}:${approvalId}:${decision}:${payloadHash}:${signedAt}`;

/**
 * Verifies a decision bundle offline: Auditail's signature over the whole file, every event hash and link in the chain
 * segment, the signed checkpoint, the receipt against the payload, the policy text against its hash, each approver's
 * own signature against their registered key, and the independent timestamp's imprint.
 */
export async function verifyBundle(bundle: Record<string, any>, opts: { account?: string; publicKeys?: PublicKeyInfo[]; keysUrl?: string } = {}): Promise<BundleReport> {
  const problems: string[] = [], notes: string[] = [], checks: string[] = [];
  const out = (): BundleReport => ({ valid: problems.length === 0, problems, notes, subject: bundle?.subject, account: bundle?.account, checks });
  if (bundle?.format !== 'auditail-decision-bundle-v1') { problems.push('not an Auditail decision bundle'); return out(); }
  let keys: PublicKeyInfo[];
  try { keys = opts.publicKeys ?? (await fetchPublicKeys(opts.keysUrl)); } catch (e) { problems.push((e as Error).message); return out(); }
  const acct = bundle.account as string;

  // 1. the file as a whole
  const sig = await verifyReport(bundle, { account: opts.account, publicKeys: keys });
  if (!sig.valid) problems.push(`signature: ${sig.reason}`); else checks.push('signed by Auditail and unchanged since it was generated');

  // 2. chain: each event recomputes; the segment is contiguous; the checkpoint vouches for its end
  const evs = (bundle.chain?.events ?? []) as EvidenceEvent[];
  for (const e of evs) if ((await sha256Hex(e.prev_hash + '\n' + eventCanonical(e))) !== e.hash) problems.push(`event #${e.seq} was modified`);
  if (bundle.chain?.contiguous) {
    for (let i = 1; i < evs.length; i++) {
      if (evs[i].seq !== evs[i - 1].seq + 1 || evs[i].prev_hash !== evs[i - 1].hash) { problems.push(`the chain segment is broken at event #${evs[i].seq}`); break; }
    }
  } else notes.push(bundle.chain?.note ?? 'the events are not a contiguous segment; check their position with a full export');
  for (const seq of bundle.chain?.relatedSeqs ?? []) if (!evs.some((e) => e.seq === seq)) problems.push(`related event #${seq} is missing from the bundle`);
  const last = evs[evs.length - 1];
  if (bundle.chain?.checkpoint && last) {
    const cp = await verifyCheckpoint(bundle.chain.checkpoint, { account: acct, publicKeys: keys });
    if (!cp.valid) problems.push(`checkpoint: ${cp.reason}`);
    else if (bundle.chain.contiguous && (cp.claims.seq !== last.seq || cp.claims.hash !== last.hash)) problems.push('the checkpoint does not match the end of the chain segment');
    else checks.push(`${evs.length} log event(s) recompute and link to a signed checkpoint (#${cp.claims.seq})`);
  }

  // 3. receipt matches the payload (checked as of when it was issued: receipts expire, evidence doesn't)
  if (bundle.receipt) {
    const tokenClaims = (() => { try { return JSON.parse(dec.decode(b64urlDecode(String(bundle.receipt).split('.')[1]))) as ReceiptClaims; } catch { return null; } })();
    const r = await verifyReceipt(bundle.receipt, { account: acct, action: bundle.summary?.action, publicKeys: keys, now: (tokenClaims?.iat ?? 0) * 1000 });
    if (!r.valid) problems.push(`receipt: ${r.reason}`);
    else {
      const ph = await sha256Hex(canonicalJson(bundle.payload));
      if (ph !== r.claims.ph) problems.push('receipt: the payload in the bundle is not the one the receipt authorized');
      else if (r.claims.aid !== bundle.subject) problems.push('receipt: it is for a different decision');
      else checks.push(`receipt ${r.claims.typ === 'approval' ? '(human approval)' : '(policy decision)'} matches the payload${r.claims.pv ? `, policy v${r.claims.pv}` : ''}${r.claims.sid ? `, session ${r.claims.sid}${r.claims.tnt ? ' (had read untrusted data)' : ''}` : ''}`);
    }
  }

  // 4. policy text matches its hash, and its version is in the chain
  if (bundle.policy) {
    if ((await sha256Hex(bundle.policy.policyJson)) !== bundle.policy.hash) problems.push('policy: the text does not match its hash');
    else {
      const pe = evs.find((e) => e.action === 'policy.updated' && e.audit_id === `pol_${bundle.policy.version}`);
      if (pe && JSON.parse(pe.payload_json).hash !== bundle.policy.hash) problems.push('policy: the hash differs from the one recorded in the log');
      checks.push(`policy v${bundle.policy.version} text matches its hash${pe ? ' and the log' : ''}`);
    }
  }

  // 5. approvers' own signatures, against keys registered in the log
  const regs = new Map<string, string>();
  for (const e of evs) if (e.action === 'approver.key_registered') { const p = JSON.parse(e.payload_json); regs.set(p.keyId, p.publicKey); }
  for (const s of (bundle.approval?.signatures ?? []) as Record<string, string>[]) {
    const ph = await sha256Hex(canonicalJson(bundle.payload));
    const expected = approvalStatement(acct, bundle.subject, s.decision as 'approve' | 'deny', ph, s.signedAt);
    if (s.statement !== expected) { problems.push(`signature by ${s.approver}: the statement is not for this account, approval and payload`); continue; }
    const pub = regs.get(s.keyId);
    if (!pub) notes.push(`signature by ${s.approver}: key ${s.keyId} registration is not in this bundle's chain segment`);
    if (pub && pub !== s.publicKey) { problems.push(`signature by ${s.approver}: the key differs from the one registered in the log`); continue; }
    let ok = false;
    try { ok = await ed25519Verify(s.publicKey, b64urlDecode(s.signature), enc.encode(s.statement)); } catch { ok = false; }
    if (!ok) problems.push(`signature by ${s.approver}: invalid`); else checks.push(`${s.approver} signed "${s.decision}" for this exact payload with their own key`);
  }

  // 6. independent timestamp
  const ts = bundle.chain?.timestamp as TimestampInfo | null;
  if (ts) {
    const e = evs.find((x) => x.seq === ts.seq);
    const p = e ? await checkTimestamp(acct, e.seq, e.hash, ts) : 'the timestamped event is not in the bundle';
    if (p) problems.push(`timestamp: ${p}`);
    else checks.push(`independent RFC 3161 timestamp from ${ts.tsa}${ts.genTime ? ` at ${ts.genTime}` : ''} covers the log up to #${ts.seq}; verify the authority's signature with openssl ts -verify -digest ${ts.imprint} -in token.der -token_in -CAfile <chain>`);
  } else notes.push('no independent timestamp covers this decision yet (they are taken hourly)');
  return out();
}
