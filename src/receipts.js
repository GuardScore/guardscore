// Signed, hash-chained receipts. Each verdict is canonicalized, hashed,
// linked to the previous receipt and signed with Ed25519, so anyone with the
// public key can confirm a result and that none were removed or reordered.
import { createHash, generateKeyPairSync, sign, verify as edVerify, createPrivateKey, createPublicKey } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';

export function canonical(v) {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object') {
    return `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

export const sha256 = s => createHash('sha256').update(s).digest('hex');

export function loadKeys(dir) {
  mkdirSync(dir, { recursive: true });
  const priv = join(dir, 'signing-key.pem');
  const pub = join(dir, 'signing-key.pub.pem');
  if (!existsSync(priv)) {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    writeFileSync(priv, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    writeFileSync(pub, publicKey.export({ type: 'spki', format: 'pem' }));
  }
  return { privateKey: createPrivateKey(readFileSync(priv)), publicKey: createPublicKey(readFileSync(pub)) };
}

function lastHash(logPath) {
  if (!existsSync(logPath)) return null;
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean);
  return lines.length ? JSON.parse(lines.at(-1)).hash : null;
}

export function issueReceipt({ logDir, body }) {
  mkdirSync(logDir, { recursive: true });
  const logPath = join(logDir, 'log.jsonl');
  const keys = loadKeys(join(logDir, 'keys'));
  const payload = { ...body, prev: lastHash(logPath) };
  const hash = sha256(canonical(payload));
  const signature = sign(null, Buffer.from(hash), keys.privateKey).toString('base64');
  const receipt = { payload, hash, signature };
  appendFileSync(logPath, JSON.stringify(receipt) + '\n');
  return receipt;
}

// Checks every signature and every link in the chain.
export function auditLog(logDir) {
  const logPath = join(logDir, 'log.jsonl');
  if (!existsSync(logPath)) return { ok: true, count: 0 };
  const { publicKey } = loadKeys(join(logDir, 'keys'));
  const lines = readFileSync(logPath, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l));
  let prev = null;
  for (const [i, r] of lines.entries()) {
    if (r.payload.prev !== prev) return { ok: false, count: lines.length, error: `chain broken at receipt ${i}` };
    if (sha256(canonical(r.payload)) !== r.hash) return { ok: false, count: lines.length, error: `hash mismatch at receipt ${i}` };
    if (!edVerify(null, Buffer.from(r.hash), publicKey, Buffer.from(r.signature, 'base64'))) {
      return { ok: false, count: lines.length, error: `bad signature at receipt ${i}` };
    }
    prev = r.hash;
  }
  return { ok: true, count: lines.length };
}
