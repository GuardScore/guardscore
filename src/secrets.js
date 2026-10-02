// Supabase secret keys in the project's files. A service-role key bypasses
// every row-level security policy, so one that reaches the browser undoes all
// the other checks (the other half of the Lovable breach).
//
// Proof is the key itself: a legacy key is a JWT whose payload says
// "role":"service_role"; a new-format secret key starts with sb_secret_. Only
// the payload is decoded; the key is never used, and reports show a redacted
// form (first 12 characters) so they don't spread the secret further.
//
// Exposure decides severity:
//   browser  shipped to users' browsers (client code, built bundles, or an env
//            var with a public prefix): a leak, the check fails
//   server   server code or a server-only env var: a warning (keep it out of git)
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const SKIP_DIRS = new Set(['node_modules', '.git', '.verified-changes', '.next', '.turbo', '.vercel', 'coverage']);
const TEXT = /\.(m?[jt]sx?|cjs|vue|svelte|astro|html?|json|ya?ml|toml)$/i;
const DOTENV = /(^|[\\/])\.env(\..+)?$/;
// Test and spec files assert about keys (often that they are NOT exposed) and
// carry dummy fixtures; they aren't shipped to users.
const TEST_FILE = /(^|[\\/])(__tests__|__mocks__)[\\/]|\.(spec|test|stories|e2e|cy)\.[jt]sx?$|(^|[\\/])(tests?|e2e|cypress|__fixtures__)[\\/]/i;
const PUBLIC_PREFIX = /^(VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_|GATSBY_|VUE_APP_)/;
const JWT = /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
const SB_SECRET = /sb_secret_[A-Za-z0-9_-]{10,}/g;
// A public-prefixed env var that names a secret, referenced from code.
const PUBLIC_SECRET_VAR = /\b((?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_|GATSBY_|VUE_APP_)[A-Z0-9_]*(?:SERVICE_ROLE|SERVICE_KEY|SECRET)[A-Z0-9_]*)\b/g;

const redact = k => `${k.slice(0, 12)}…`;

function jwtRole(token) {
  try {
    const p = JSON.parse(Buffer.from(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    // The local-development keys every `supabase start` prints (issuer
    // "supabase-demo") are public and only work against a local stack.
    if (p.iss === 'supabase-demo') return null;
    return typeof p.role === 'string' ? p.role : null;
  } catch { return null; }
}

// Where does this file end up? Server-only locations first.
function fileSide(rel, text) {
  const p = rel.split(sep).join('/');
  if (/(^|\/)(supabase\/functions|api|server|backend|functions|scripts|migrations)\//.test(p)) return 'server';
  if (/(^|\/)(server|middleware)\.[mc]?[jt]s$/.test(p) || /route\.[jt]sx?$/.test(p) || /\.server\.[jt]sx?$/.test(p)) return 'server';
  if (/^\s*['"]use server['"]/m.test(text) || /from ['"]server-only['"]/.test(text)) return 'server';
  if (/(^|\/)(src|app|components|pages|public|dist|build|out|www|static|lib)\//.test(p) || /\.html?$/.test(p)) return 'browser';
  if (/['"]use client['"]/.test(text)) return 'browser';
  return 'server';
}

function* walk(dir, root = dir) {
  let entries;
  try { entries = readdirSync(dir); } catch { return; }
  for (const e of entries) {
    if (SKIP_DIRS.has(e)) continue;
    const p = join(dir, e);
    let st;
    try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* walk(p, root);
    else if (st.size < 2_000_000 && (TEXT.test(e) || DOTENV.test(e)) && !TEST_FILE.test(relative(root, p))) yield p;
  }
}

export function scanSecrets(dir) {
  const findings = [];
  for (const file of walk(dir)) {
    const rel = relative(dir, file);
    let text;
    try { text = readFileSync(file, 'utf8'); } catch { continue; }
    const lines = text.split('\n');
    const isEnv = DOTENV.test(rel);
    lines.forEach((line, i) => {
      const keys = [...line.matchAll(JWT)].map(m => ({ key: m[0], role: jwtRole(m[0]) }))
        .concat([...line.matchAll(SB_SECRET)].map(m => ({ key: m[0], role: 'service_role (sb_secret_ key)' })));
      for (const { key, role } of keys) {
        if (!role || !/service_role/.test(role)) continue; // anon/publishable keys are meant to be public
        let side;
        if (isEnv) {
          const name = line.split('=')[0].trim().replace(/^export\s+/, '');
          side = PUBLIC_PREFIX.test(name) ? 'browser' : 'server';
        } else side = fileSide(rel, text);
        findings.push({ file: rel, line: i + 1, side, kind: 'service_role_key', proof: key.startsWith('sb_secret_') ? `key ${redact(key)} is a Supabase secret key (sb_secret_ prefix)` : `key ${redact(key)} decodes to "role": "service_role"` });
      }
      // Client code reading a public-prefixed variable that holds a secret: the
      // build inlines its value into the bundle even though it isn't in the repo.
      if (!isEnv && !TEST_FILE.test(rel) && fileSide(rel, text) === 'browser') {
        for (const m of line.matchAll(PUBLIC_SECRET_VAR)) {
          findings.push({ file: rel, line: i + 1, side: 'browser', kind: 'public_secret_env', proof: `browser code reads ${m[1]}; the build inlines public-prefixed variables into the bundle` });
        }
      }
    });
  }
  return findings;
}

// As gauntlet-style results: browser exposure is a proven leak, server-side a warning.
export function secretResults(dir) {
  const found = scanSecrets(dir);
  const results = found.filter(f => f.side === 'browser').map((f, i) => ({
    id: `secrets.${f.kind}.${i}`, table: f.file, class: 'service_key_exposed', kind: 'attack', status: 'leaked',
    proof: { actor: 'anyone who opens the app', sql: `${f.file}:${f.line}`, observed: { exposure: f.proof } },
  }));
  const warnings = found.filter(f => f.side === 'server').map(f => ({ file: f.file, line: f.line, detail: `service-role key in server-side ${f.file}:${f.line} (${f.proof}); fine on a server, never commit it` }));
  return { results, warnings };
}
