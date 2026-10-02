// Feature parity with the other Supabase checkers, built on the same private
// copy this tool already makes from the migrations:
//   - snapshot: record the security-relevant state (RLS on/off, every policy's
//     command and expression, and the grants to anon/authenticated) to a file.
//   - diff: build the copy as it is now and compare it to a saved snapshot,
//     reporting only the changes that matter for security (a policy dropped, a
//     rule opened up to `true`, RLS turned off, a new grant to anon).
//   - scanCode: a static scan of the app's server code and config for the
//     things that live outside row-level security — a webhook with no signature
//     check, an API route that trusts a client-sent price or role, a payment
//     amount taken from the request. These are reported as warnings, not proven
//     attacks, because they aren't in the database.
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { buildDb } from './db.js';

// The security state of the built copy, as plain data.
export async function captureState(migrationSql) {
  const db = await buildDb({ migrations: [migrationSql], seed: '' });
  try {
    const tables = (await db.query(`select c.relname as t, c.relrowsecurity as rls
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relkind in ('r', 'p') order by c.relname`)).rows;
    const policies = (await db.query(`select tablename as t, policyname as name, cmd,
      array_to_string(roles, ',') as roles, coalesce(qual, '') || ' | ' || coalesce(with_check, '') as expr
      from pg_policies where schemaname = 'public' order by tablename, policyname`)).rows;
    const grants = (await db.query(`select table_name as t, grantee, string_agg(privilege_type, ',' order by privilege_type) as privs
      from information_schema.role_table_grants where table_schema = 'public' and grantee in ('anon', 'authenticated')
      group by table_name, grantee order by table_name, grantee`)).rows;
    const state = {};
    for (const r of tables) state[r.t] = { rls: r.rls, policies: {}, grants: {} };
    for (const p of policies) (state[p.t] ||= { rls: false, policies: {}, grants: {} }).policies[`${p.cmd}:${p.name}`] = { roles: p.roles, expr: p.expr.trim() };
    for (const g of grants) (state[g.t] ||= { rls: false, policies: {}, grants: {} }).grants[g.grantee] = g.privs;
    return { version: 1, capturedAt: new Date().toISOString(), tables: state };
  } finally { await db.close(); }
}

const isTrue = x => /^\s*\(?\s*true\s*\)?\s*(\|\s*(\(?\s*true\s*\)?)?\s*)?$/i.test(String(x || '').trim());

// Compare a saved snapshot to the current state; return security-relevant changes.
export function diffState(before, after) {
  const changes = [];
  const b = before.tables || {}, a = after.tables || {};
  for (const t of Object.keys(a)) {
    const bt = b[t], at = a[t];
    if (!bt) { changes.push({ table: t, severity: 'info', change: `new table "${t}"${at.rls ? '' : ' with row level security OFF'}` }); continue; }
    if (bt.rls && !at.rls) changes.push({ table: t, severity: 'high', change: `row level security was turned OFF on "${t}"` });
    for (const key of Object.keys(bt.policies)) if (!at.policies[key]) changes.push({ table: t, severity: 'high', change: `policy dropped on "${t}": ${key}` });
    for (const key of Object.keys(at.policies)) {
      const bp = bt.policies[key], ap = at.policies[key];
      if (!bp) { changes.push({ table: t, severity: isTrue(ap.expr) ? 'high' : 'info', change: `new policy on "${t}": ${key}${isTrue(ap.expr) ? ' with an always-true rule' : ''}` }); continue; }
      if (!isTrue(bp.expr) && isTrue(ap.expr)) changes.push({ table: t, severity: 'high', change: `policy "${key}" on "${t}" was opened to an always-true rule` });
      if (!/anon/.test(bp.roles) && /anon/.test(ap.roles)) changes.push({ table: t, severity: 'high', change: `policy "${key}" on "${t}" now applies to anonymous visitors` });
    }
    for (const role of ['anon', 'authenticated']) {
      const bg = bt.grants[role] || '', ag = at.grants[role] || '';
      const added = ag.split(',').filter(p => p && !bg.includes(p));
      if (added.length) changes.push({ table: t, severity: role === 'anon' ? 'high' : 'medium', change: `${role} was granted ${added.join(', ')} on "${t}"` });
    }
  }
  return changes;
}

// --- Static code scan (the part that isn't in the database) --------------
const CODE = /\.(m?[jt]sx?|cjs|vue|svelte|astro|py|rb|go)$/;
const SKIP = new Set(['node_modules', '.git', 'dist', 'build', '.next', 'out', 'coverage', '.vercel', 'vendor', '__pycache__']);
function* walk(dir, root = dir) {
  let entries; try { entries = readdirSync(dir); } catch { return; }
  for (const e of entries) {
    if (SKIP.has(e)) continue;
    const p = join(dir, e);
    let st; try { st = statSync(p); } catch { continue; }
    if (st.isDirectory()) yield* walk(p, root);
    else if (st.size < 1_000_000 && CODE.test(e)) yield [p, relative(root, p)];
  }
}
const isServer = rel => /(\/|^)(api|server|functions|supabase\/functions|app\/api|pages\/api|routes|webhooks?|actions)(\/|$)|route\.[jt]s|\.server\.[jt]s|edge/i.test(rel);

// Warnings, not proven attacks: code the database can't vouch for.
export function scanCode(dir) {
  const out = [];
  for (const [file, rel] of walk(dir)) {
    let text; try { text = readFileSync(file, 'utf8'); } catch { continue; }
    const low = text.toLowerCase();
    // Stripe / payment webhooks that never verify the signature.
    if (/webhook/i.test(rel + text) && /stripe/i.test(text) && !/constructevent|verifyheader|webhook.*secret|stripe-signature/i.test(text) && /\bstripe\b/i.test(text))
      out.push({ file: rel, rule: 'webhook-no-signature', severity: 'high', detail: 'a Stripe webhook handler that never calls stripe.webhooks.constructEvent / verifies the stripe-signature header: anyone can POST a fake payment event' });
    // A payment amount or price taken from the request body (client-controlled).
    if (isServer(rel) && /stripe|checkout|payment|charge|paymentintent/i.test(text) && /(req|request)\.(body|json|query)[^;\n]*\b(amount|price|total|unit_amount|quantity)\b/i.test(text))
      out.push({ file: rel, rule: 'amount-from-client', severity: 'high', detail: 'a charge/checkout amount or price is read from the request instead of looked up on the server: a buyer can set their own price' });
    // A role/admin flag read from the request body and trusted.
    if (isServer(rel) && /(req|request)\.(body|json)[^;\n]*\b(role|is_admin|isadmin|admin|is_premium|plan|tier)\b/i.test(text) && !/=== *('|")?(admin)/i.test(text))
      out.push({ file: rel, rule: 'role-from-client', severity: 'medium', detail: 'a role/plan/admin field is taken from the request body; if it is written to the database, a user can grant themselves that role' });
    // A server route / edge function that writes with the service-role key but
    // has no visible auth check on the caller.
    if (isServer(rel) && /service_role|service-role|serviceRoleKey|SUPABASE_SERVICE/i.test(text)
        && !/auth\.getuser|getsession|verifyjwt|requireauth|authorization|bearer|req\.auth|ctx\.user|getServerSession|clerk|jwt\.verify/i.test(low))
      out.push({ file: rel, rule: 'service-role-no-auth', severity: 'high', detail: 'this route uses the service-role key (which bypasses row level security) but has no visible check of who is calling it' });
  }
  // De-dup by rule+file.
  const seen = new Set();
  return out.filter(f => { const k = f.rule + f.file; if (seen.has(k)) return false; seen.add(k); return true; });
}
