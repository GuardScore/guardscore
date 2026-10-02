// Instant, in-browser static pre-check — the zero-install front door.
//
// This is NOT the attack engine. The engine builds a private Postgres copy and
// PROVES each hole by attacking it. This file reads the migration SQL as text
// and flags only the holes that are unambiguous from the DDL alone, so it can
// run in a browser in milliseconds with no database and no install.
//
// Design rule, because trust is the whole product: UNDER-report, never
// over-report. Everything flagged here is true from the SQL text. Things that
// need a live attack to confirm (or to clear) are left to the full engine, and
// the UI says so. A green result here means "no obvious hole in the DDL," not
// "proven safe" — that word is reserved for the engine.
//
// Every finding reuses the engine's own EXPLAIN wording (kept in sync by
// test/web-scan.js) so the fast scan and the deep scan never contradict.

export const EXPLAIN = {
  anon_read: 'Anyone on the internet, without logging in, can read this table.',
  anon_write: 'Anyone on the internet, without logging in, can change or delete rows in this table.',
  cross_user_read: "Any logged-in user can read other users' rows.",
  cross_user_write: "Any logged-in user can change or delete other users' rows.",
  self_grant_admin: 'Any user can make themselves an admin by setting their own role, and your access rules trust that role.',
  privileged_tamper: 'A user can set money, status or entitlement fields on their own rows (mark their own order paid, set a price to 0, add credits, upgrade their own plan) that only staff or the server should set.',
  shared_data_write: 'Any signed-in user can change or delete rows that belong to nobody in particular (a product catalog, settings), for example set every price to 0.',
  public_bucket: "A storage bucket whose name says it holds private files is public: anyone with a file's URL can download it, whatever the storage policies say.",
  storage_upload: 'People who should not can upload files here: an open upload into a bucket that is also publicly readable lets anyone host content under your domain.',
  definer_exposed: 'A function that runs with its owner’s rights is left runnable by anonymous or signed-in callers, so anyone can call it.',
  rls_lockout: 'Row level security is on but the table has no policies, so no ordinary user can read or write it — this locks your own app out unless every access goes through the service role.',
};

// The one-line fix shown next to each finding.
const FIX = {
  no_rls: t => `Enable row level security and add owner-scoped policies:\n  alter table ${t} enable row level security;\n  create policy "${t}_own" on ${t} for all to authenticated\n    using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));`,
  allow_all_read: t => `Replace the always-true read rule with an owner check:\n  using ( user_id = (select auth.uid()) )`,
  allow_all_write: t => `Replace the always-true write rule with an owner check:\n  using ( user_id = (select auth.uid()) ) with check ( user_id = (select auth.uid()) )`,
  anon_grant: t => `Revoke the grant to anonymous visitors:\n  revoke all on ${t} from anon;`,
  self_grant: (t, col) => `Stop users from writing "${col}" themselves — move role/entitlement changes to a server-only path, or add a WITH CHECK that pins it:\n  with check ( ${col} = (select ${col} from ${t} where id = (select auth.uid())) )`,
  public_bucket: b => `Make the bucket private and serve files through signed URLs:\n  update storage.buckets set public = false where id = '${b}';`,
  anon_upload: b => `Limit uploads to signed-in users writing their own folder:\n  with check ( bucket_id = '${b}' and (storage.foldername(name))[1] = (select auth.uid())::text )`,
  definer: fn => `Revoke the function from anonymous and signed-in callers, leave it to the server:\n  revoke all on function ${fn} from anon, authenticated;`,
  rls_lockout: t => `Add the policies your app needs, e.g. an owner policy:\n  create policy "${t}_own" on ${t} for all to authenticated using (user_id = (select auth.uid()));`,
};

// ---- tiny SQL splitter (comment-safe, dollar-quote-safe) ----------------
function statements(sql) {
  let s = String(sql || '');
  // strip line comments and block comments (not inside strings — good enough for DDL)
  s = s.replace(/--[^\n]*/g, ' ').replace(/\/\*[\s\S]*?\*\//g, ' ');
  const out = [];
  let buf = '';
  let i = 0;
  let dollar = null; // current dollar-quote tag, e.g. $$ or $func$
  let inStr = false;
  while (i < s.length) {
    const c = s[i];
    if (dollar) {
      if (s.startsWith(dollar, i)) { buf += dollar; i += dollar.length; dollar = null; continue; }
      buf += c; i++; continue;
    }
    if (inStr) { buf += c; if (c === "'") { if (s[i + 1] === "'") { buf += "'"; i += 2; continue; } inStr = false; } i++; continue; }
    if (c === "'") { inStr = true; buf += c; i++; continue; }
    const dq = /^\$[a-zA-Z_]*\$/.exec(s.slice(i));
    if (dq) { dollar = dq[0]; buf += dollar; i += dollar.length; continue; }
    if (c === ';') { if (buf.trim()) out.push(buf.trim()); buf = ''; i++; continue; }
    buf += c; i++;
  }
  if (buf.trim()) out.push(buf.trim());
  return out;
}

// Schema-qualified? Supabase's API only exposes the `public` schema (and any a
// project explicitly adds) to anon/authenticated, so a table in stripe.*,
// fulla.*, a *_private schema etc. is not anon-reachable and we never flag it.
const schemaOf = n => { const m = /^"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s*\./.exec(String(n || '')); return m ? m[1].toLowerCase() : 'public'; };
const norm = n => String(n || '').replace(/"/g, '').replace(/^public\./i, '').toLowerCase();
const USER_COL = /(^|_)(user_id|owner(_id)?|author(_id)?|created_by|account_id|profile_id|customer_id|uid)$/i;
// Columns whose exposure to anonymous visitors is a leak by any reading — never
// a "public catalog / leaderboard" by design. Used to keep an anon-readable
// table from being dismissed as a public catalog.
const SENSITIVE_COL = /(^|_)(email|phone|mobile|address|full_name|first_name|last_name|ssn|dob|date_of_birth|national_id|passport|password|password_hash|secret|api_key|access_token|refresh_token|stripe_\w+|card_\w+|iban|token)$/i;
const ROLE_COL = /(^|_)(role|is_admin|isadmin|admin|is_staff|is_superuser|plan|tier|subscription(_\w+)?|is_pro|premium|credits?|balance|verified|approved)$/i;
const PRIVATE_BUCKET = /id_?cards?|docs?|documents?|invoices?|receipts?|private|secure|contracts?|passports?|medical|reports?|backups?|exports?|attachments?|uploads?|files?/i;
const SERVER_TABLE = /(^|_)(oauth|token|tokens|credential|secret|webhook|stripe|billing|integration|sync|audit|log|logs|event|events|migration|schema_migration|cron|queue|outbox)(_|s|$)/i;

// ---- the scan -----------------------------------------------------------
export function staticScan(sql) {
  const stmts = statements(sql);
  const tables = {}; // name -> { cols:Set, rls:bool, policies:[], userData:bool }
  const table = n => (tables[n] ||= { name: n, cols: new Set(), rls: false, policies: [], userData: false, roleCols: [] });
  const buckets = {}; // id -> { public:bool }
  const grants = []; // { table, roles }
  const objectPolicies = []; // storage.objects policies
  const defexec = []; // { fn, roles } explicit execute grants to anon/public
  const definerFns = new Set();

  for (const st of stmts) {
    const low = st.toLowerCase();

    // create table
    let m = /^create\s+table\s+(?:if\s+not\s+exists\s+)?([^\s(]+)\s*\(([\s\S]*)\)/i.exec(st);
    if (m) {
      const name = norm(m[1]);
      if (schemaOf(m[1]) !== 'public') continue; // only the API-exposed schema
      const t = table(name);
      // split columns at top level commas
      const body = m[2];
      let depth = 0, cur = '', cols = [];
      for (const ch of body) { if (ch === '(') depth++; else if (ch === ')') depth--; if (ch === ',' && depth === 0) { cols.push(cur); cur = ''; } else cur += ch; }
      if (cur.trim()) cols.push(cur);
      for (const c of cols) {
        const cm = /^\s*"?([a-zA-Z_][a-zA-Z0-9_]*)"?\s+/.exec(c);
        if (!cm) continue;
        const cn = cm[1].toLowerCase();
        if (/^(constraint|primary|foreign|unique|check|exclude|like)$/i.test(cn)) continue;
        t.cols.add(cn);
        if (USER_COL.test(cn)) t.userData = true;
        if (/(^|_)(email|phone|full_name|first_name|last_name|address|ssn|dob|date_of_birth)$/i.test(cn)) t.userData = true;
        if (ROLE_COL.test(cn)) t.roleCols.push(cn);
      }
      continue;
    }

    // enable RLS
    m = /^alter\s+table\s+(?:if\s+exists\s+)?([^\s]+)\s+enable\s+row\s+level\s+security/i.exec(st);
    if (m) { if (schemaOf(m[1]) === 'public') table(norm(m[1])).rls = true; continue; }

    // create policy
    m = /^create\s+policy\s+("(?:[^"]|"")*"|\S+)\s+on\s+([^\s]+)([\s\S]*)$/i.exec(st);
    if (m) {
      const on = norm(m[2]);
      const isStorage = /storage\s*\.\s*objects/i.test(m[2]) || on === 'objects';
      if (!isStorage && schemaOf(m[2]) !== 'public') continue; // non-public schema, not API-exposed
      const rest = m[3];
      const cmd = (/\bfor\s+(select|insert|update|delete|all)\b/i.exec(rest) || [, 'all'])[1].toLowerCase();
      const roles = (/\bto\s+([a-z_,\s"]+?)(?=\s+(using|with)\b|$)/i.exec(rest) || [, ''])[1].toLowerCase();
      const using = (/\busing\s*\(([\s\S]*?)\)\s*(with\s+check|$)/i.exec(rest) || [, ''])[1];
      const check = (/\bwith\s+check\s*\(([\s\S]*)\)\s*$/i.exec(rest) || [, ''])[1];
      const pol = { cmd, roles, using: using.trim(), check: check.trim(), restrictive: /\bas\s+restrictive\b/i.test(rest) };
      if (isStorage) objectPolicies.push(pol);
      else table(on).policies.push(pol);
      continue;
    }

    // grants to anon / public (only anon — a plain `to public` on a table Postgres
    // gives to PUBLIC by default is not a signal on its own).
    m = /^grant\s+([\s\S]+?)\s+on\s+(?:table\s+)?([^\s]+)\s+to\s+([a-z_,\s"]+)/i.exec(st);
    if (m && !/function|routine|procedure|schema|sequence/i.test(low.slice(0, m[0].indexOf(' on ')))) {
      const to = m[3].toLowerCase();
      if (/\banon\b/.test(to) && !/usage/i.test(m[1]) && schemaOf(m[2]) === 'public') grants.push({ table: norm(m[2]), roles: to, privs: m[1].trim().toLowerCase() });
    }

    // security definer functions + explicit execute grants
    if (/create\s+(or\s+replace\s+)?function/i.test(low) && /security\s+definer/i.test(low)) {
      const fm = /function\s+([a-zA-Z0-9_."]+)\s*\(/i.exec(st);
      if (fm) definerFns.add(norm(fm[1]).replace(/\(.*$/, ''));
    }
    m = /^grant\s+execute\s+on\s+function\s+([^\s(]+)[\s\S]*?\s+to\s+([a-z_,\s"]+)/i.exec(st);
    if (m && /\banon\b|\bpublic\b/.test(m[2].toLowerCase())) defexec.push({ fn: norm(m[1]), roles: m[2].toLowerCase() });

    // storage buckets
    if (/insert\s+into\s+storage\s*\.\s*buckets/i.test(low)) {
      // columns list + values
      const cm = /\(([^)]*)\)\s*values?\s*([\s\S]*)/i.exec(st);
      if (cm) {
        const colNames = cm[1].split(',').map(x => x.trim().replace(/"/g, '').toLowerCase());
        const pubIdx = colNames.indexOf('public');
        // each value tuple
        const tuples = cm[2].match(/\(([^)]*)\)/g) || [];
        for (const tup of tuples) {
          const vals = tup.slice(1, -1).split(',').map(x => x.trim());
          const idIdx = colNames.indexOf('id');
          const id = idIdx >= 0 && vals[idIdx] ? vals[idIdx].replace(/^'|'$/g, '') : (vals[0] || '').replace(/^'|'$/g, '');
          const isPublic = pubIdx >= 0 ? /true/i.test(vals[pubIdx] || '') : false;
          if (id) buckets[id] = { public: isPublic };
        }
      }
    }
  }

  const isTrue = x => /^\s*\(?\s*true\s*\)?\s*$/i.test(x || '');
  // A policy anonymous visitors can use: role is explicitly anon, or the policy
  // has no `to` clause (defaults to PUBLIC, which includes anon). `to public` is
  // treated the same. `to authenticated` is NOT anon.
  const anonPol = r => !r.trim() || /\banon\b/.test(r) || /\bpublic\b/.test(r);
  const findings = [];
  const add = (sev, cls, tbl, why, fix) => findings.push({ severity: sev, class: cls, table: tbl, what: EXPLAIN[cls] || why, fix });
  const sensitive = t => [...t.cols].some(c => SENSITIVE_COL.test(c));

  // Precision over recall. We flag as a *hole* (verdict unsafe) only what is
  // unambiguous from the DDL and essentially never intended: anonymous WRITE,
  // and anonymous READ of a table that carries sensitive personal data. An
  // anonymous READ of an ordinary table could be a public catalog or
  // leaderboard, so it is a review-warning the full engine settles — never a
  // scary red on its own. Authenticated-user issues (cross-user reads, shared
  // workspaces, self-granted roles) are left entirely to the attack engine,
  // which is the only thing that can tell a leak from an intended design.
  const flagAnonWrite = (t, how) => add('critical', 'anon_write', t.name, EXPLAIN.anon_write, how);
  const flagAnonRead = (t, how) => sensitive(t)
    ? add('critical', 'anon_read', t.name, `Anyone, without logging in, can read this table — and it holds personal data (email, phone or similar).`, how)
    : add('warning', 'anon_read', t.name, `This table looks readable by anyone without logging in. That is fine for a public catalog or leaderboard, but a leak otherwise — the full verifier confirms by attacking it.`, how);

  for (const t of Object.values(tables)) {
    let anonRead = false, anonWrite = false;
    // NOTE: grants to anon are NOT a signal. Supabase auto-grants ALL on every
    // public table to anon and authenticated by default (you see it in every
    // `remote_schema.sql` dump); row level security, not the grant, is the gate.
    // So access is decided purely by RLS state and policies below — the same
    // reason the full engine has to attack rather than read grants.
    // Allow-all policies open to anon.
    for (const p of t.policies) {
      if (p.restrictive || !anonPol(p.roles)) continue;
      if ((p.cmd === 'select' || p.cmd === 'all') && isTrue(p.using)) anonRead = true;
      if ((p.cmd === 'update' || p.cmd === 'delete' || p.cmd === 'all') && (isTrue(p.using) || isTrue(p.check))) anonWrite = true;
      if (p.cmd === 'insert' && isTrue(p.check)) anonWrite = true; // anon insert: spam/injection, essentially never intended
    }
    // RLS never enabled on a public-schema table Postgres exposes to the API:
    // the grants decide, which we can't see statically, so this is a warning the
    // full engine settles — unless it also carries sensitive data, when an
    // unlocked table is worth a red.
    const noRls = !t.rls && !t.policies.length && !SERVER_TABLE.test(t.name);
    if (anonWrite) flagAnonWrite(t, FIX.allow_all_write(t.name));
    if (anonRead) flagAnonRead(t, FIX.allow_all_read(t.name));
    if (noRls && !anonWrite && !anonRead) {
      if (sensitive(t)) add('critical', 'anon_write', t.name, `Row level security is off on this table and it holds personal data, so anyone the database exposes it to can read or change it.`, FIX.no_rls(t.name));
      else add('warning', 'rls_lockout', t.name, `Row level security is not enabled on this table. If Supabase exposes it to the anon role (the default for public tables), anyone can read and write it — the full verifier confirms.`, FIX.no_rls(t.name));
    } else if (t.rls && !t.policies.length && !SERVER_TABLE.test(t.name)) {
      add('warning', 'rls_lockout', t.name, EXPLAIN.rls_lockout, FIX.rls_lockout(t.name));
    }
  }

  // A private-named bucket marked public = true: simple and precise. Open-upload
  // detection needs to weigh several storage.objects policies against each other,
  // which is exactly the kind of thing the attack engine does reliably and a
  // text scan does not, so it is left to the full verifier.
  for (const [id, b] of Object.entries(buckets)) {
    if (b.public && PRIVATE_BUCKET.test(id)) add('high', 'public_bucket', `storage: ${id}`, EXPLAIN.public_bucket, FIX.public_bucket(id));
  }
  // Whether a security-definer function is truly exposed depends on the interplay
  // of GRANT/REVOKE and Supabase's default routine grants — the attack engine
  // resolves it by calling the function as anon; a text scan guesses. Left to it.
  void defexec;

  // De-dup identical (class, table).
  const seen = new Set();
  const uniq = findings.filter(f => { const k = f.class + '|' + f.table; if (seen.has(k)) return false; seen.add(k); return true; });
  const order = { critical: 0, high: 1, warning: 2 };
  uniq.sort((a, b) => order[a.severity] - order[b.severity]);

  const crit = uniq.filter(f => f.severity === 'critical' || f.severity === 'high').length;
  const warn = uniq.filter(f => f.severity === 'warning').length;
  const tableCount = Object.keys(tables).length;
  // Same shape as the engine's Guard Score: any real leak caps at 59, warnings
  // cap at 79, otherwise a clean DDL scans at 100. Never claims "proven".
  let guardScore;
  if (crit) guardScore = Math.max(12, 59 - 8 * (crit - 1));
  else if (warn) guardScore = Math.max(70, 79 - 3 * (warn - 1));
  else guardScore = 100;

  return {
    mode: 'static',
    guardScore,
    verdict: crit ? 'unsafe' : warn ? 'review' : (tableCount ? 'no_obvious_holes' : 'nothing_to_scan'),
    tableCount,
    counts: { critical: uniq.filter(f => f.severity === 'critical').length, high: uniq.filter(f => f.severity === 'high').length, warning: warn },
    findings: uniq,
  };
}
