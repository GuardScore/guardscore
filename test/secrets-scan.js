// Leaked-secret scanner: catches real secrets, and (the hard part) never flags
// keys that are meant to be public — Supabase anon key, Firebase web config,
// NEXT_PUBLIC_/VITE_ vars, Stripe publishable key.
import { scanSecrets } from '../web/secrets-scan.js';

let fail = 0;
const ok = (c, m) => { if (!c) { fail++; console.log('  FAIL', m); } };

const jwt = role => {
  const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${b64({ role, iss: 'supabase', iat: 1 })}.c2lnbmF0dXJlLXBsYWNlaG9sZGVy`;
};

/* ---------- true positives ---------- */
const svc = scanSecrets([{ path: 'src/lib/db.ts', content: `export const admin = createClient(url, "${jwt('service_role')}")` }]);
ok(svc.verdict === 'unsafe' && svc.findings.some(f => f.class === 'supabase_service_role'), 'flags a Supabase service_role key');
ok(svc.findings.every(f => !/eyJ/.test(f.table) && !/eyJ/.test(f.what)), 'never echoes the secret value back');

ok(scanSecrets([{ path: 'api.js', content: 'const s = "sk_live_abcdEFGH1234567890 zzz"' }]).findings.some(f => f.class === 'stripe_secret'), 'flags a Stripe secret key');
ok(scanSecrets([{ path: 'key.pem', content: '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----' }]).findings.some(f => f.class === 'private_key'), 'flags a PEM private key');
ok(scanSecrets([{ path: 'deploy.sh', content: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' }]).findings.some(f => f.class === 'aws_key'), 'flags an AWS access key');
ok(scanSecrets([{ path: 'sa.json', content: '{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----","client_email":"x@y.iam"}' }]).findings.some(f => f.class === 'gcp_sa_key'), 'flags a GCP service-account key');
ok(scanSecrets([{ path: 'ci.yml', content: 'token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' }]).findings.some(f => f.class === 'provider_token'), 'flags a GitHub token');
ok(scanSecrets([{ path: '.env', content: 'SUPABASE_SERVICE_ROLE_KEY=abcdef1234567890abcdef' }]).findings.some(f => f.class === 'env_committed' || f.class === 'supabase_service_role'), 'flags a committed .env with secrets');

/* ---------- true negatives (must NOT flag public-by-design keys) ---------- */
const anon = scanSecrets([{ path: 'src/supabase.ts', content: `const supabase = createClient(url, "${jwt('anon')}")` }]);
ok(anon.verdict === 'clear' && !anon.findings.length, 'does NOT flag the Supabase anon key (public by design)');

const fb = scanSecrets([{ path: 'firebase.ts', content: 'const firebaseConfig = { apiKey: "AIzaSyA-EXAMPLE-1234567890abcdefgHIJKL", authDomain: "x.firebaseapp.com" }' }]);
ok(!fb.findings.length, 'does NOT flag the Firebase web config apiKey (public by design)');

ok(!scanSecrets([{ path: '.env.local', content: 'NEXT_PUBLIC_API_URL=https://api.example.com\nNEXT_PUBLIC_ANALYTICS=abc123def456' }]).findings.length, 'does NOT flag NEXT_PUBLIC_ vars');
ok(!scanSecrets([{ path: 'checkout.tsx', content: 'const stripe = loadStripe("pk_live_51ABCdefGHIjklMNOpqrs")' }]).findings.length, 'does NOT flag the Stripe publishable key');
ok(scanSecrets([{ path: 'clean.ts', content: 'const x = 1; export function add(a,b){return a+b}' }]).guardScore === 100, 'clean file → Guard Score 100');

// placeholders / examples in docs and starter templates must NOT flag
ok(!scanSecrets([{ path: 'README.md', content: 'STRIPE_SECRET_KEY=sk_live_xxxxxxxxxxxxxxxxxxxx' }]).findings.length, 'does NOT flag an xxxx placeholder key');
ok(!scanSecrets([{ path: '.env.example', content: 'OPENAI_KEY=sk-your_api_key_here' }]).findings.length, 'does NOT flag a your_api_key_here placeholder');
ok(!scanSecrets([{ path: 'config.ts', content: 'const token = "<YOUR_GITHUB_TOKEN>"' }]).findings.length, 'does NOT flag an angle-bracket placeholder');

console.log(fail ? `secrets-scan: ${fail} failed` : 'secrets-scan checks passed (leaked-secret / frontend exposure scanner)');
process.exit(fail ? 1 : 0);
