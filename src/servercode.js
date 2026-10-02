// Server code that skips row level security: Supabase Edge Functions and API
// routes that use the service-role key. That key ignores every policy, so the
// code itself has to check who is calling. These are read, not attacked (the
// functions aren't run), so each one comes back as a warning naming the file,
// the line where the admin client is made, and what's missing.
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const SKIP = new Set(['node_modules', '.git', '.next', '.verified-changes', 'dist', 'build']);
const SERVER_FILE = /(^|\/)(supabase\/functions\/[^/]+\/.*|pages\/api\/.*|app\/.*\/route|api\/.*|server\/.*|netlify\/functions\/.*)\.(m?[jt]sx?)$/;

function* walk(dir) {
  let entries = [];
  try { entries = readdirSync(dir); } catch { return; }
  for (const e of entries) {
    if (SKIP.has(e)) continue;
    const p = join(dir, e);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* walk(p);
    else if (st.size < 500_000) yield p;
  }
}

const ADMIN_CLIENT = /(SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE|serviceRole|service_role|sb_secret_)/;
const CHECKS_CALLER = /auth\.getUser\s*\(|auth\.getClaims\s*\(|auth\.getSession\s*\(|jwtVerify|verifyJWT|verify\(\s*token|getServerSession|currentUser\s*\(|auth\(\)\s*;?|clerkClient|requireUser|requireAuth|getUserFromRequest/;
const TAKES_INPUT = /req\.json\s*\(|request\.json\s*\(|searchParams|req\.query|req\.body|params\.|formData\s*\(/;
const WRITES_OR_READS = /\.from\(\s*['"`][\w.]+['"`]\s*\)\s*\.(select|update|delete|insert|upsert)|\.rpc\(/;

export function serverCodeChecks(dir) {
  const out = [];
  for (const file of walk(dir)) {
    const rel = relative(dir, file).split(sep).join('/');
    if (!SERVER_FILE.test(rel)) continue;
    const text = readFileSync(file, 'utf8');
    if (!ADMIN_CLIENT.test(text) || !WRITES_OR_READS.test(text)) continue;
    const line = text.split('\n').findIndex(l => ADMIN_CLIENT.test(l)) + 1;
    if (!CHECKS_CALLER.test(text)) {
      out.push({ level: 'warn', file: rel, line, setting: 'service-role client without a caller check',
        detail: `uses the service-role key (which skips every row level security policy) and never checks who is calling${TAKES_INPUT.test(text) ? ', while acting on ids or data from the request' : ''}: anyone who can reach this endpoint can read or change any user's data through it. Check the caller (auth.getUser() with their token) and scope every query to them, or use the caller's own token instead of the service-role key` });
    } else if (!/\.eq\(\s*['"`](user_id|owner_id|created_by|author_id|profile_id|customer_id|team_id|org_id)['"`]/.test(text)) {
      out.push({ level: 'warn', file: rel, line, setting: 'service-role queries not limited to the caller',
        detail: 'looks at who is calling, but then queries with the service-role key without limiting rows to that user (no .eq("user_id", user.id) or similar), so every user gets everyone\'s rows; filter by the caller, or query with the caller\'s own token so row level security applies' });
    }
  }
  // Edge Functions deployed without JWT verification accept calls from anyone.
  const cfg = join(dir, 'supabase', 'config.toml');
  if (existsSync(cfg)) {
    let fn = null;
    readFileSync(cfg, 'utf8').split('\n').forEach((l, i) => {
      const sec = l.match(/^\s*\[functions\.([^\]]+)\]/);
      if (sec) fn = sec[1].replace(/"/g, "");
      else if (/^\s*\[/.test(l)) fn = null;
      if (fn && /^\s*verify_jwt\s*=\s*false/.test(l)) out.push({ level: 'info', file: 'supabase/config.toml', line: i + 1, setting: `functions.${fn}.verify_jwt`,
        detail: `Edge Function "${fn}" accepts calls without a signed-in user's token; fine for webhooks that check their own signature, risky for anything else` });
    });
  }
  return out;
}
