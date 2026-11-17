/**
 * For approvers who decide through the API (a back-office service or script) rather than the dashboard:
 * generate an Ed25519 signing key, register its public key once (POST /v1/approver-keys with your approver token),
 * then sign each decision. Keep the private key in your secret store or HSM; Auditail never sees it.
 */
import { canonicalJson, sha256Hex } from './shared';
import { approvalStatement } from './verify';

const b64url = (b: Uint8Array) => {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return (typeof btoa === 'function' ? btoa(s) : Buffer.from(b).toString('base64')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/** A new Ed25519 key pair. publicKey is what you register; store privateKeyJwk (or keep privateKey in memory). */
export async function generateApproverKey(): Promise<{ publicKey: string; privateKey: CryptoKey; privateKeyJwk: JsonWebKey }> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { publicKey: b64url(raw), privateKey: pair.privateKey, privateKeyJwk: await crypto.subtle.exportKey('jwk', pair.privateKey) };
}

/** Imports a private key saved with generateApproverKey(). */
export async function importApproverKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
}

/**
 * Signs a decision. `payload` is the approval's payload exactly as returned by GET /v1/approvals/{id}: the hash is
 * computed here, from what you reviewed, not taken from the server. Send the result as `signature` in
 * POST /v1/approvals/{id}/decision.
 */
export async function signApproval(o: { account: string; approvalId: string; decision: 'approve' | 'deny'; payload: unknown; keyId: string; privateKey: CryptoKey; signedAt?: string }):
  Promise<{ keyId: string; signedAt: string; signature: string }> {
  const signedAt = o.signedAt ?? new Date().toISOString();
  const statement = approvalStatement(o.account, o.approvalId, o.decision, await sha256Hex(canonicalJson(o.payload)), signedAt);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, o.privateKey, new TextEncoder().encode(statement)));
  return { keyId: o.keyId, signedAt, signature: b64url(sig) };
}
