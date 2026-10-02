// Leaked-secret / frontend-exposure scanner. Reads source text (frontend code,
// committed .env, config) and flags credentials that must never ship to a client
// or a public repo. Precision-first, like the other front-door scanners: it
// UNDER-reports rather than false-alarm, and it deliberately does NOT flag keys
// that are designed to be public — the Supabase anon key, the Firebase web config
// (apiKey/authDomain/...), and NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_ variables — because
// flagging those trains people to ignore the tool.
//
// A leaked *secret* is game-over regardless of RLS: the Supabase service_role key
// bypasses row-level security entirely. So this runs alongside the attack engine.

export const EXPLAIN = {
  supabase_service_role: 'This is a Supabase service_role key. It bypasses row level security completely — anyone who has it can read and write every row in your database. It must never appear in client code or a public repo.',
  private_key: 'A private key / credential is committed here. Anyone who can see this file can use it.',
  stripe_secret: 'A Stripe secret key (sk_live/sk_test) is exposed. It can charge cards and read your Stripe account.',
  openai_key: 'An API key is exposed. Anyone with it can spend against your account.',
  aws_key: 'An AWS access key is exposed. It can act on your AWS account.',
  gcp_sa_key: 'A Google service-account private key is committed. It grants server-side access to your Google Cloud/Firebase project.',
  provider_token: 'A provider access token (GitHub/Slack/SendGrid/Twilio) is exposed and can act on that account.',
  env_committed: 'An environment file with secret values appears to be committed. Secrets in it are exposed to anyone with repo access.',
};

const FIX = {
  rotate: what => `Rotate this credential now (assume it is compromised), then move it to a server-side environment variable that never ships to the client:\n  - remove it from the code and from git history\n  - store it in your host's server env (not NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_)\n  - ${what}`,
};

// Detectors. Each: {class, severity, re, note}. Ordered most-severe first.
// `re` matches the SECRET itself (kept out of any output — we report location + class, never the value).
const DETECTORS = [
  // Supabase service_role JWT: a JWT whose payload contains "role":"service_role".
  { class: 'supabase_service_role', severity: 'critical',
    test: s => /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/.test(s) && jwtIsServiceRole(s),
    fix: 'reach Supabase only through the anon key on the client; use service_role only in trusted server code.' },
  { class: 'gcp_sa_key', severity: 'critical',
    test: s => /"type"\s*:\s*"service_account"/.test(s) && /"private_key"\s*:\s*"-----BEGIN/.test(s),
    fix: 'delete the service-account JSON from the repo, rotate the key in Google Cloud IAM, and load it from a secret manager on the server.' },
  { class: 'private_key', severity: 'critical',
    test: s => /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/.test(s),
    fix: 'remove the private key, rotate it, and keep private keys out of any client bundle or repo.' },
  { class: 'stripe_secret', severity: 'critical',
    test: s => /\bsk_(?:live|test)_[A-Za-z0-9]{16,}/.test(s) || /\brk_(?:live|test)_[A-Za-z0-9]{16,}/.test(s),
    fix: 'call Stripe from your server only; the browser should never see a secret or restricted key.' },
  { class: 'aws_key', severity: 'critical',
    test: s => /\bAKIA[0-9A-Z]{16}\b/.test(s),
    fix: 'rotate the IAM key and use short-lived server-side credentials instead.' },
  { class: 'provider_token', severity: 'high',
    test: s => /\bgh[pousr]_[A-Za-z0-9]{30,}\b/.test(s) || /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/.test(s) || /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/.test(s) || /\bAC[a-z0-9]{32}\b/.test(s),
    fix: 'revoke the token on the provider and issue a server-only replacement.' },
  { class: 'openai_key', severity: 'high',
    test: s => /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/.test(s) && !/\bsk_(?:live|test)_/.test(s),
    fix: 'proxy the API through your server so the key stays server-side.' },
];

// Obvious placeholders / examples in docs and starter templates — not real secrets.
// Suppressing these is the difference between a tool people trust and one they mute.
const PLACEHOLDER = /x{5,}|placeholder|your[_-]?(api[_-]?)?(key|token|secret|password)|<[^>]{0,40}>|\$\{|changeme|change[_-]?me|dummy|foobar|redacted|replace[_-]?(this|me)|\.example\b/i;

// Keys that are SAFE to be public — never flag these, even though they look key-ish.
const PUBLIC_SAFE = [
  /NEXT_PUBLIC_[A-Z0-9_]+/, /VITE_[A-Z0-9_]+/, /EXPO_PUBLIC_[A-Z0-9_]+/,
  /apiKey\s*[:=]/, // Firebase web config apiKey is public by design
  /publishableKey|pk_(?:live|test)_/, // Stripe publishable key is public
];

function b64urlDecode(s) {
  try { return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'); }
  catch { try { return atob(s.replace(/-/g, '+').replace(/_/g, '/')); } catch { return ''; } }
}
function jwtIsServiceRole(text) {
  const m = text.match(/eyJ[A-Za-z0-9_-]{10,}\.([A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}/);
  if (!m) return false;
  const payload = b64urlDecode(m[1]);
  return /"role"\s*:\s*"service_role"/.test(payload);
}

// Real env files carry live secrets; .env.example/.sample/.template/.dist are
// placeholder templates and must never be flagged.
const isEnvFile = p => /(^|\/)\.env(\.local|\.development|\.production|\.prod|\.dev|\.staging)?$/i.test(String(p || ''));

// files: [{ path, content }]. Returns findings (no secret values, ever).
export function scanSecrets(files) {
  const findings = [];
  const seen = new Set();
  const add = (severity, cls, path, line, fix) => {
    const k = cls + '|' + path;
    if (seen.has(k)) return; seen.add(k);
    findings.push({ severity, class: cls, table: path + (line ? `:${line}` : ''), what: EXPLAIN[cls], fix: FIX.rotate(fix) });
  };

  for (const f of (files || [])) {
    const path = f.path || '(source)';
    const content = String(f.content || '');
    const lines = content.split('\n');
    for (const d of DETECTORS) {
      // find first offending line for a location; skip lines that are clearly a public-safe assignment
      for (let i = 0; i < lines.length; i++) {
        const ln = lines[i];
        if (PUBLIC_SAFE.some(rx => rx.test(ln)) && d.class !== 'gcp_sa_key' && d.class !== 'private_key') continue;
        if (PLACEHOLDER.test(ln) && d.class !== 'private_key' && d.class !== 'gcp_sa_key') continue; // skip obvious dummy/example values
        if (d.test(ln)) { add(d.severity, d.class, path, i + 1, d.fix); break; }
      }
      // multi-line secrets (PEM, service-account JSON) — test whole content too
      if (!seen.has(d.class + '|' + path) && (d.class === 'private_key' || d.class === 'gcp_sa_key') && d.test(content)) {
        add(d.severity, d.class, path, 0, d.fix);
      }
    }
    // A committed real .env with a non-placeholder secret assignment.
    const envSecretLine = isEnvFile(path) && content.split('\n').some(l => /(_KEY|_SECRET|_TOKEN|SERVICE_ROLE|PASSWORD|PRIVATE)\s*=\s*\S{12,}/i.test(l) && !PLACEHOLDER.test(l));
    if (envSecretLine && !seen.has('env_committed|' + path)) {
      add('high', 'env_committed', path, 0, 'add this file to .gitignore, purge it from git history, and set the values as host env vars.');
    }
  }

  const order = { critical: 0, high: 1, warning: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  const critical = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high').length;
  let guardScore;
  if (critical) guardScore = Math.max(0, 40 - 10 * (critical - 1)); // a live secret is game-over → very low
  else if (high) guardScore = Math.max(60, 79 - 5 * (high - 1));
  else guardScore = 100;

  return { stack: 'secrets', guardScore, verdict: critical ? 'unsafe' : high ? 'review' : 'clear', counts: { critical, high, warning: 0 }, findings };
}
