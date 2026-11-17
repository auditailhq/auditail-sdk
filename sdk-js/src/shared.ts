/** Helpers shared by the client and the verifiers. Redaction and canonical JSON must stay identical everywhere. */

export const DEFAULT_REDACT = [
  'password', 'passwd', 'secret', 'token', 'apikey', 'api_key', 'authorization', 'auth',
  'ssn', 'creditcard', 'credit_card', 'cardnumber', 'card_number', 'cvv', 'privatekey', 'private_key',
];

export function redactSet(extra: string[] = []): Set<string> {
  return new Set([...DEFAULT_REDACT, ...extra].map((k) => k.toLowerCase()));
}

export function redact(value: unknown, keys: Set<string>, depth = 0): unknown {
  if (depth > 10) return '[TRUNCATED]';
  if (Array.isArray(value)) return value.map((v) => redact(v, keys, depth + 1));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = keys.has(k.toLowerCase()) ? '[REDACTED]' : redact(v, keys, depth + 1);
    }
    return out;
  }
  return value;
}

/** Deterministic JSON: object keys sorted, no whitespace. Matches the Auditail server and the Python SDK. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v) ?? 'null';
  if (Array.isArray(v)) return '[' + v.map((x) => (x === undefined ? 'null' : canonicalJson(x))).join(',') + ']';
  const o = v as Record<string, unknown>;
  return '{' + Object.keys(o).sort().filter((k) => o[k] !== undefined).map((k) => JSON.stringify(k) + ':' + canonicalJson(o[k])).join(',') + '}';
}

const enc = new TextEncoder();

export async function sha256Hex(text: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle) {
    const d = await subtle.digest('SHA-256', enc.encode(text));
    return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, '0')).join('');
  }
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

export function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  if (typeof atob === 'function') return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

/** Verifies an Ed25519 signature. Uses Web Crypto when available, else node:crypto. */
export async function ed25519Verify(publicKeyB64url: string, signature: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<boolean> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle) {
    try {
      const key = await subtle.importKey('raw', b64urlDecode(publicKeyB64url), { name: 'Ed25519' }, false, ['verify']);
      return await subtle.verify({ name: 'Ed25519' }, key, signature, data);
    } catch {
      // fall through to node:crypto (older runtimes without Ed25519 in Web Crypto)
    }
  }
  const nodeCrypto = await import('node:crypto');
  const key = nodeCrypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKeyB64url }, format: 'jwk' });
  return nodeCrypto.verify(null, data, key, signature);
}
