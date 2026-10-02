// Read a Supabase project folder the way Supabase applies it: migrations in
// filename order, plus the tables the builder declared public.
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { readToml } from './config.js';

// supabase/migrations/*.sql in filename order (that's how Supabase applies them).
// If the agent put its SQL somewhere else, fall back to every .sql file in the
// project except seeds, in path order, and say so.
// excludeFile (absolute path) is left out: verify_change treats it as the change.
export function loadMigrations(dir, excludeFile = null) {
  const migDir = join(dir, 'supabase', 'migrations');
  let files = existsSync(migDir) ? readdirSync(migDir).filter(f => f.endsWith('.sql')).sort().map(f => join(migDir, f)) : [];
  if (excludeFile) {
    const all = files;
    files = files.filter(f => f !== excludeFile);
    // Only migrations before the change make up "the app as it is".
    const at = all.indexOf(excludeFile);
    if (at >= 0) files = all.slice(0, at);
  }
  let layout = 'supabase/migrations';
  if (!files.length) {
    files = walk(dir).filter(f => f.endsWith('.sql') && !/seed/i.test(f)).sort();
    layout = files.length ? 'other .sql files' : 'none';
  }
  // Each file is its own script: a last statement without a semicolon must not
  // run into the next file's first one.
  // Supabase runs each migration file in a fresh session, so a pg_dump header
  // (search_path emptied, function-body checks off, a role switch) ends with it.
  const reset = `\n;\nreset role;\nselect pg_catalog.set_config('search_path', '"$user", public, extensions', false);\nset check_function_bodies = on;\nset row_security = on;\n`;
  let sql = files.map(f => `-- file: ${relative(dir, f)}\n${readFileSync(f, 'utf8').replace(/^\uFEFF/, '')}${reset}`).join('\n\n');
  const moved = [];
  ({ sql } = exposeSchemas(dir, sql, moved));
  return { sql, files: files.map(f => relative(dir, f)), layout, movedSchemas: moved };
}

function walk(d) {
  const out = [];
  for (const e of readdirSync(d)) {
    if (e === 'node_modules' || e.startsWith('.')) continue;
    const p = join(d, e);
    if (statSync(p).isDirectory()) out.push(...walk(p)); else out.push(p);
  }
  return out;
}

// What the agent declared public. The checker honours it; the scorer never does.
export function loadDeclared(dir) {
  const f = join(dir, 'verified-changes.json');
  if (!existsSync(f)) return {};
  try {
    const j = JSON.parse(readFileSync(f, 'utf8'));
    return { publicTables: j.publicTables || [], sharedTables: j.sharedTables || [] };
  } catch { return {}; }
}

// Declarations need reasons. Declaring a table open is how an agent can make a
// leak disappear, so each one must say why the data is meant to be open. An
// entry is "table: reason" (or "table - reason"), {table, reason}, or, in
// verified-changes.json, an object {table: reason}. Without a real reason (one
// that talks about the data, not about passing the check) the declaration is
// ignored and the table is checked as private. Declarations of tables whose
// names look private are honoured but flagged in the report and the receipt.
// Matched against each word of the table name (user_messages -> user, messages).
const PRIVATE_WORD = /^(messages?|chats?|inbox|dms?|orders?|payments?|invoices?|billing|transactions?|wallets?|banks?|payouts?|salar(y|ies)|payroll|notes?|journals?|diar(y|ies)|health|medical|patients?|sessions?|tokens?|secrets?|passwords?|credentials?|keys?|admins?|roles?|permissions?|address(es)?|contacts?|phones?|emails?|documents?|uploads?|files?|private|audits?|logs?)$/i;
const looksPrivate = name => name.split(/[_\W]+/).some(w => PRIVATE_WORD.test(w));
const VACUOUS_REASON = /^(n\/?a|none|todo|tbd|test|testing|needed|required|yes|ok|public|shared|because|fix|temp)\.?$|\b(so (that )?(the )?(check|verifier|test|scan)s? pass|to pass|silence|suppress|make (it|the check) (pass|safe)|stop (the )?(warning|error|finding))/i;

const OWN_ONLY = /\b(only (their|his|her|your) own|their own|own (data|rows|records|orders|items)|only (the )?(owner|user who)|belongs? to (them|the user))\b/i;

export function parseDeclarations(entries, scope) {
  const list = Array.isArray(entries) ? entries
    : entries && typeof entries === 'object' ? Object.entries(entries).map(([table, reason]) => ({ table, reason }))
    : [];
  return list.map(e => {
    let table, reason;
    if (typeof e === 'string') {
      const m = e.match(/^\s*([^:\s]+)\s*(?::|\s[-\u2013\u2014]\s)\s*(.*)$/);
      table = (m ? m[1] : e).trim(); reason = (m ? m[2] : '').trim();
    } else if (e && typeof e === 'object') { table = String(e.table || e.name || '').trim(); reason = String(e.reason || '').trim(); }
    if (!table) return null;
    const flags = [];
    if (looksPrivate(table)) flags.push('the table name suggests private data');
    // A reason about the check rather than the data doesn't count as a reason,
    // and neither does one that describes owner-only access ("users can read
    // only their own"): that table is private, and declaring it open would
    // switch off exactly the attacks that protect it.
    const empty = !reason || reason.length < 12 || VACUOUS_REASON.test(reason);
    const ownOnly = !!reason && OWN_ONLY.test(reason);
    if (ownOnly) flags.push('the reason describes owner-only access, so the table is private and is checked as private');
    return { table, scope, reason: reason || null, honoured: !empty && !ownOnly, flags };
  }).filter(Boolean);
}

// The manifest a check runs with, from verified-changes.json plus tool arguments.
export function buildManifest(dir, { public_tables = [], shared_tables = [] } = {}) {
  const f = join(dir, 'verified-changes.json');
  let j = {};
  if (existsSync(f)) { try { j = JSON.parse(readFileSync(f, 'utf8')); } catch {} }
  const declarations = [
    ...parseDeclarations(j.publicTables, 'public'), ...parseDeclarations(public_tables, 'public'),
    ...parseDeclarations(j.sharedTables, 'shared'), ...parseDeclarations(shared_tables, 'shared'),
  ];
  const ok = scope => declarations.filter(d => d.honoured && d.scope === scope).map(d => d.table);
  return { publicTables: exact(ok('public')), sharedTables: exact(ok('shared')), declarations };
}

// Table names become exact-match patterns.
export const exact = names => (names || []).map(n => `^${String(n).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);

// Data in its own schema (sticky.tasks) that config.toml exposes to the API
// ([api] schemas = ["public", "sticky"]). The checker works on public, so the
// schema's objects are loaded there. What the schema itself kept out stays
// out: without USAGE for anon, anon gets no table privileges.
const SYSTEM_SCHEMAS = /^(public|graphql_public|graphql|storage|auth|extensions|realtime|vault|cron|net|pgsodium|supabase_functions|pg_catalog|information_schema)$/i;
export function exposeSchemas(dir, sql, moved = []) {
  const f = join(dir, 'supabase', 'config.toml');
  if (!existsSync(f)) return { sql };
  const listed = (readToml(readFileSync(f, 'utf8'))['api.schemas']?.value || '').match(/"([^"]+)"/g)?.map(x => x.slice(1, -1)) || [];
  let tail = '';
  for (const sch of listed.filter(x => !SYSTEM_SCHEMAS.test(x) && /^\w+$/.test(x))) {
    if (!new RegExp(`create\\s+schema\\s+(if\\s+not\\s+exists\\s+)?"?${sch}"?`, 'i').test(sql)) continue;
    // A table of the same name in public would collide: leave it alone.
    const names = [...sql.matchAll(new RegExp(`create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?"?${sch}"?\\."?(\\w+)"?`, 'gi'))].map(m => m[1]);
    if (names.some(n => new RegExp(`create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?(?:"?public"?\\.)?"?${n}"?\\s*\\(`, 'i').test(sql.replace(new RegExp(`"?${sch}"?\\."?${n}"?`, 'gi'), '')))) continue;
    // Tables in a custom schema get no automatic privileges (public's default
    // grants to anon and authenticated don't apply there): afterwards, clear
    // them and replay only the schema's own grant and revoke statements.
    const privStmts = [...sql.matchAll(new RegExp(`(?:^|;|\\n)\\s*((?:grant|revoke)\\b[^;]*\\b${sch}\\b[^;]*;)`, 'gi'))].map(m => m[1]).filter(x => !/\bschema\b[^;]*\bto\b|usage\s+on\s+schema|on\s+schema/i.test(x) || /all\s+(tables|sequences|functions|routines)\s+in\s+schema/i.test(x));
    const anonUsage = new RegExp(`grant\\s+[^;]*usage[^;]*on\\s+schema\\s+[^;]*\\b${sch}\\b[^;]*to\\s+[^;]*\\b(anon|public)\\b`, 'i').test(sql);
    sql = sql
      .replace(new RegExp(`create\\s+schema\\s+(if\\s+not\\s+exists\\s+)?"?${sch}"?[^;]*;`, 'gi'), `-- (schema ${sch} loaded into public by the checker)\n;`)
      .replace(new RegExp(`(\\bschema\\s+)"?${sch}"?\\b`, 'gi'), '$1public')
      .replace(new RegExp(`(?<![\\w."])"?${sch}"?\\.(?=["\\w])`, 'g'), 'public.')
      .replace(new RegExp(`(search_path\\s*(?:=|to)\\s*[^;\\n]*?)\\b${sch}\\b`, 'gi'), '$1public');
    const rw = x => x.replace(new RegExp(`(\\bschema\\s+)"?${sch}"?\\b`, 'gi'), '$1public').replace(new RegExp(`(?<![\\w."])"?${sch}"?\\.(?=["\\w])`, 'g'), 'public.');
    tail += `\n-- privileges of schema ${sch}, as the app set them\n${names.map(n => `revoke all on public."${n}" from anon, authenticated;`).join('\n')}\n${privStmts.filter(x => !/\bfunction|routines/i.test(x)).map(rw).join('\n')}\n`;
    if (!anonUsage) tail += `\nrevoke all on all tables in schema public from anon;\nrevoke all on all sequences in schema public from anon;\n`;
    moved.push(sch);
  }
  return { sql: sql + tail };
}
