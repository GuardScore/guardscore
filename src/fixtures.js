// Automatic sample data. An agent invents its own schema, so there is no seed
// file to lean on; an empty table would "block" every attack and prove nothing.
// This fills every empty public table with one row for user A and one for user B,
// following foreign keys, so every table can be attacked.
//
// Rules, chosen so a sample row is private unless the app says otherwise:
//  - columns that point at a user get the row's own user (A or B)
//  - a row that points at another table points at the same user's parent row
//  - memberships put A in group A and B in group B, with the group's top role
//  - user-level role columns get the least-privileged value
//  - nullable columns stay null (so share tokens and public flags stay unset);
//    booleans named like private/hidden get true, public/shared/published false
//  - tables that look like share links or invitations are left empty: a row
//    there would grant access on purpose, so they are reported as not tested;
//    so are tables whose rows make a user privileged (staff, admins)
//  - primary keys get fixed values, so the same rows can be rebuilt on real
//    Supabase and every attack refers to the same ids
// Every row is inserted with the matching user's JWT claims set, so triggers
// that read auth.uid() behave as they would for that user. The SQL actually
// applied is returned, so the remote runner can replay it.
import { IDS, EMAILS } from './db.js';
import { fitCheck, splitTopLevel, stripParens } from './checkfit.js';
import { loadCatalog, identityTables, userMatch, authText, ORDINARY_ROLE, userFkCols, findMemberships, ROLE_COL, ADMIN_BOOL_COL, roleValues, highestRole, USER_COL_NAMES } from './catalog.js';

const q = n => `"${n.replace(/"/g, '""')}"`;
const lit = v => `'${String(v).replace(/'/g, "''")}'`;
// Share-link and invitation tables: only B shares or invites, so A's content
// stays private and the attacks can tell "B shared this on purpose" from a leak.
const SHARE_TABLE = /shar(e|ed|ing)|invit|(public|access|magic)_?links?/i;
// A token column on a content row: B's row gets one (B shared it), A's stays null.
export const SHARE_TOKEN_COL = /^(share|sharing|public|link|access|invite)_?(token|code|slug|key|hash)$|^(share|public)_?(url|link|id)$/i;
const PRIVILEGE_TABLE = /admin|staff|moderator|superuser|operator/i;
const PRIVATE_BOOL = /private|hidden|secret|draft|locked/i;
const PUBLIC_BOOL = /public|shared|published|visible|listed|approved|featured/i;
const PREFERRED_VALUE = /^(private|draft|hidden|pending|personal|user|member|viewer|customer|basic|free)$/i;

export async function autoFixtures(db, manifest = {}) {
  if (manifest.autoFixtures === false) return { sql: '', filled: [], failed: [], skipped: [], privilegeProbes: {}, shareTables: [] };
  const catalog = await loadCatalog(db);
  // A lookup that may fail (a guessed column, a type mismatch) must not abort
  // the surrounding transaction of a warm check.
  const tryQuery = async (sql, params = []) => {
    if (db.nested) await db.exec('savepoint vc_try');
    try { const r = await db.query(sql, params); if (db.nested) await db.exec('release savepoint vc_try'); return r; }
    catch { if (db.nested) await db.exec('rollback to savepoint vc_try; release savepoint vc_try'); return { rows: [] }; }
  };
  const byName = new Map(catalog.map(t => [t.name, t]));
  const identity = identityTables(catalog);
  const memberships = findMemberships(catalog);
  const membershipTables = new Set(memberships.map(m => m.table));
  const groups = [...new Set(memberships.map(m => m.group))];
  const skipCfg = manifest.tables || {};
  // In a table meant to be public (a product catalog, published reviews) sample
  // rows keep the app's own defaults, so "published"/"approved" rows are visible
  // as the app intends; everywhere else they are forced private.
  const isPublicTable = name => !!skipCfg[name]?.publicRead || (manifest.publicTables || []).some(p => new RegExp(p, 'i').test(name));

  const polRows = (await db.query(`select tablename as t, coalesce(qual, '') || ' ' || coalesce(with_check, '') as x from pg_policies where schemaname = 'public'`)).rows;
  const uidOwned = (name, c) => polRows.some(r => r.t === name && new RegExp(`(?<![\\w.])(${name}\\.)?"?${c}"?\\s*=\\s*\\(?\\s*(select\\s+)?auth\\.uid\\(\\)|auth\\.uid\\(\\)(\\s+as\\s+\\w+)?\\s*\\)?\\s*=\\s*(${name}\\.)?"?${c}"?(?![\\w"])`, 'i').test(r.x));
  const emailOwned = name => {
    for (const r of polRows.filter(r => r.t === name)) {
      const m = r.x.match(/(?:lower\()?\(?"?(\w*email\w*)"?\)?\s*=\s*(?:lower\()?\s*\(?\s*(?:coalesce\()?\s*\(?\s*\(?auth\.jwt\(\)\s*->>\s*'email'/i);
      if (m) return m[1];
    }
    return null;
  };
  // Privilege tables by what the app does with them, not only by name: the
  // table an is_platform_host() / has_admin_access() helper (no arguments: a global role, not a per-team one) looks the caller up
  // in makes whoever is listed privileged, so sample rows don't go there.
  const privilegeTables = new Set((await tryQuery(`select p.proname as n, p.prosrc as src from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname in ('public', 'private') and p.prorettype = 'bool'::regtype and p.pronargs = 0 and p.proname ~* '^(is|has|can)_'
      and p.proname ~* '(host|admin|staff|moderator|operator|super|platform|root|support|maintainer|owner|manager|editor)'`)).rows
    .flatMap(f => [...f.src.matchAll(/\bfrom\s+(?:public\.)?"?(\w+)"?/gi)].map(m => m[1]))
    .filter(t => byName.has(t) && !/^(profiles?|users?|accounts?)$/i.test(t)));
  // Does a would-be row pass one CHECK? Asked of the database, with the
  // row's values (or the column defaults) as a one-row derived table.
  const satisfies = async (t, def, values) => {
    const expr = def.replace(/^CHECK\s*/i, '').replace(/\s+NOT VALID\s*$/i, '');
    const cols = t.columns.filter(c => !c.generated && new RegExp(`(^|[^\\w])"?${c.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"?([^\\w]|$)`).test(expr)).map(c => {
      const v = values[c.name] !== undefined ? values[c.name] : c.hasDefault && c.defaultExpr && !/nextval/i.test(c.defaultExpr) ? c.defaultExpr : 'null';
      return `(${v})::${c.type} as ${q(c.name)}`;
    });
    if (db.nested) await db.exec('savepoint vc_check_eval');
    try {
      if (!cols.length) { if (db.nested) await db.exec('release savepoint vc_check_eval'); return false; }
      const r = await db.query(`select (${expr}) is not false as ok from (select ${cols.join(', ')}) x`);
      if (db.nested) await db.exec('release savepoint vc_check_eval');
      return r.rows[0]?.ok === true;
    } catch {
      if (db.nested) await db.exec('rollback to savepoint vc_check_eval; release savepoint vc_check_eval');
      return false;
    }
  };
  const checkCache = new Map();
  const checksOf = async name => {
    if (!checkCache.has(name)) checkCache.set(name, (await tryQuery(`select pg_get_constraintdef(oid) as d from pg_constraint where contype = 'c' and conrelid = $1::regclass`, [`public.${q(name)}`])).rows.map(r => r.d));
    return checkCache.get(name);
  };
  let counter = 0;
  const detUuid = () => `00000000-0000-4000-8000-f${String(++counter).padStart(11, '0')}`;
  const inserted = new Map(); // table -> { A: row, B: row }
  const emitted = [];
  const filled = [];
  const failed = [];
  const skipped = [];
  // For staff/admin tables: the row user B would insert to make themselves
  // privileged. Not inserted here; the gauntlet tries it as user B.
  const privilegeProbes = {};
  const shareTables = [];

  const rowCount = async t => Number((await db.query(`select count(*)::int as n from public.${q(t)}`)).rows[0].n);

  // Find the parent row that belongs to a side, for tables we didn't fill ourselves.
  async function parentRow(table, side) {
    const p = byName.get(table);
    const T = `public.${q(table)}`;
    const uid = IDS[side];
    // A team this side is actually a member of (made by the app's own signup
    // trigger, say) beats a sample team nobody belongs to.
    const mm = p && memberships.find(x => x.group === table);
    if (mm) {
      const r = (await tryQuery(`select to_jsonb(x) as r from ${T} x where ${q(mm.groupPk)} in (select ${q(mm.groupCol)} from public.${q(mm.table)} where ${userMatch(catalog, mm.table, mm.userCol)}) limit 1`, [uid])).rows[0]?.r;
      if (r) return r;
    }
    if (inserted.get(table)?.[side]) return inserted.get(table)[side];
    if (!p) return null;
    const userCol = userFkCols(p)[0] || USER_COL_NAMES.find(n => p.columns.some(c => c.name === n && c.category === 'U'));
    const tries = [];
    if (userCol) tries.push([`select to_jsonb(x) as r from ${T} x where ${q(userCol)} = $1 limit 1`, [uid]]);
    const idt = identity.find(it => it.table === table);
    if (idt) tries.push([`select to_jsonb(x) as r from ${T} x where ${q(idt.authCol)}::text = $1::text limit 1`, [uid]]);
    const m = memberships.find(mm => mm.group === table);
    if (m) tries.push([`select to_jsonb(x) as r from ${T} x where ${q(m.groupPk)} in (select ${q(m.groupCol)} from public.${q(m.table)} where ${userMatch(catalog, m.table, m.userCol)}) limit 1`, [uid]]);
    if (!userCol && !m) tries.push([`select to_jsonb(x) as r from ${T} x limit 1 offset ${side === 'B' ? 1 : 0}`, []]);
    for (const [sql, params] of tries) {
      const r = (await db.query(sql, params)).rows[0]?.r;
      if (r) return r;
    }
    return null;
  }

  async function valueFor(t, col, side, isMembership) {
    if (col.generated) return undefined;
    const pkSingle = t.pk.length === 1 && t.pk[0] === col.name;
    const userFks = userFkCols(t);
    const fk = t.fks.find(f => f.col === col.name);

    if (userFks.includes(col.name)) return lit(IDS[side]);
    // The app's own users table: its sign-in column holds the test user's id.
    if (identity.some(it => it.table === t.name && it.authCol === col.name)) return lit(IDS[side]);
    // The table's own rules say this column holds the signed-in user's id
    // (owner_user_id = auth.uid()), even without a foreign key to auth.users.
    if (col.category === 'U' && uidOwned(t.name, col.name)) return lit(IDS[side]);
    // Owned through the token subject (col = auth.jwt() ->> 'sub'): the sign-in id as text.
    if (col.category === 'S' && polRows.some(r => r.t === t.name && new RegExp(`(?<![\\w.])(${t.name}\\.)?"?${col.name}"?\\s*=\\s*\\(?\\s*(coalesce\\(\\s*)?(\\(\\s*)*(select\\s+)?auth\\.jwt\\(\\)(\\s+as\\s+\\w+)?\\s*\\)?\\s*->>\\s*'sub'`, 'i').test(r.x))) return lit(IDS[side]);
    if (fk && fk.refSchema === 'public' && fk.refTable !== t.name) {
      const parent = await parentRow(fk.refTable, side);
      if (parent && parent[fk.refCol] != null) return lit(parent[fk.refCol]);
      return col.notNull ? null : 'null';
    }
    // A file in Storage (documents.storage_object_id): upload a sample file
    // owned by this side, the way the app's upload step would.
    if (fk && fk.refSchema === 'storage' && fk.refTable === 'objects') {
      let v = null;
      if (db.nested) await db.exec('savepoint vc_storage_fixture');
      try {
        // The app's own bucket (its storage rules are written for it), else ours.
        const bucket = (await db.query(`select id from storage.buckets where id <> 'vc-fixtures' order by public, id limit 1`)).rows[0]?.id || 'vc-fixtures';
        if (bucket === 'vc-fixtures') await db.exec(`insert into storage.buckets (id, name) values ('vc-fixtures', 'vc-fixtures') on conflict do nothing`);
        const r = await db.query(`insert into storage.objects (bucket_id, name, owner, owner_id) values ($3, $1, $2::uuid, $2::text) returning ${q(fk.refCol)}::text as v`,
          [`${IDS[side]}/sample-${++counter}.txt`, IDS[side], bucket]);
        v = r.rows[0]?.v ?? null;
        if (db.nested) await db.exec('release savepoint vc_storage_fixture');
      } catch {
        if (db.nested) await db.exec('rollback to savepoint vc_storage_fixture; release savepoint vc_storage_fixture');
      }
      return v != null ? lit(v) : (col.notNull ? null : 'null');
    }
    if (fk && fk.refSchema === 'storage' && fk.refTable === 'buckets') return lit('vc-fixtures');
    if (fk && fk.refTable === t.name) return col.notNull ? null : 'null';
    if (pkSingle) {
      if (col.category === 'U') {
        const gi = groups.indexOf(t.name);
        if (gi === 0) return lit(side === 'A' ? IDS.ORG_A : IDS.ORG_B);
        return lit(detUuid());
      }
      if (col.category === 'N') return String(1000 + (++counter));
      if (col.category === 'S') return lit(`${t.name}_${side.toLowerCase()}_${++counter}`);
    }
    if (USER_COL_NAMES.includes(col.name) && col.category === 'U') return lit(IDS[side]);
    if (ROLE_COL.test(col.name) || (ADMIN_BOOL_COL.test(col.name) && col.category === 'B')) {
      if (isMembership) return lit(highestRole(col));
      const rv = roleValues(col);
      if (rv) {
        if (col.hasDefault && col.category !== 'B' && !/admin|owner|staff|super/i.test(col.defaultExpr || '')) return undefined; // the app's own default role
        return lit(rv.low);
      }
    }
    if (SHARE_TOKEN_COL.test(col.name) && (col.category === 'S' || col.category === 'U') && !col.notNull) {
      if (side !== 'B') return undefined;
      return col.category === 'U' ? lit(detUuid()) : lit(`tok-b-${t.name}-${++counter}`);
    }
    // Account gates: the rules only let in users whose is_active / approved flag
    // is set (where id = uid and is_active = true). Real users have been let in.
    if (col.category === 'B' && /^(is_)?(active|approved|enabled|verified|allowed|activated|onboarded|confirmed)$/i.test(col.name)
      && authText(catalog).some(x => new RegExp(`(?<![\\w.])(\\w+\\.)?"?${col.name}"?\\s*(=\\s*true|is\\s+true)`, 'i').test(x))) return 'true';
    if (col.category === 'B' && !isPublicTable(t.name)) {
      if (PRIVATE_BOOL.test(col.name)) return 'true';
      // A keeps everything private (the attacks aim at A's rows); B publishes,
      // so the checker can also confirm published rows stay visible.
      if (PUBLIC_BOOL.test(col.name)) return side === 'B' ? 'true' : 'false';
    }
    // A roles array (users.roles text[]): an ordinary member's role, from the
    // roles the app's rules check for ('admin' = any(roles), roles &&
    // array['coach', 'parent']). An empty list is usually "not a member yet".
    if (col.category === 'A' && /^(roles|user_roles|app_roles|role_list)$/i.test(col.name) && !isMembership) {
      const esc = col.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const seen = new Set();
      for (const x of authText(catalog)) {
        for (const m of x.matchAll(new RegExp(`"?${esc}"?\\s*(?:&&|@>|<@)\\s*(?:array\\s*)?\\[([^\\]]*)\\]|'(\\w+)'(?:::text)?\\s*=\\s*any\\s*\\(\\s*(?:\\w+\\.)?"?${esc}"?`, 'gi'))) {
          for (const v of (m[1] || `'${m[2]}'`).matchAll(/'(\w+)'/g)) seen.add(v[1]);
        }
      }
      const ORDER = ['member', 'user', 'parent', 'customer', 'client', 'student', 'viewer', 'reader', 'guest', 'player'];
      const low = ORDER.find(r => seen.has(r)) || [...seen].find(r => !/admin|owner|staff|manager|moderator|editor|super|coach|teacher|root/i.test(r));
      if (low) return `array[${lit(low)}]::${col.type}`;
    }
    if (col.values?.length && !col.hasDefault) {
      return lit(col.values.find(v => PREFERRED_VALUE.test(v)) || col.values[0]);
    }
    if (col.values?.length && col.category === 'S' && /visib|privacy|access|audience/i.test(col.name)) {
      const v = col.values.find(x => /private|only_?me|owner|hidden/i.test(x));
      if (v) return lit(v);
    }
    if (col.hasDefault || col.identity) return undefined;
    if (!col.notNull) return undefined;
    // Required column with no default: make up a plausible value.
    const who = side === 'A' ? 'alice' : side === 'C' ? 'carol' : 'bob';
    // Rows owned by email (policy: lower(email) = auth.jwt() ->> 'email') carry
    // the test user's own sign-in email.
    if (/email/i.test(col.name) && col.category === 'S' && emailOwned(t.name) === col.name) return lit(EMAILS[IDS[side]]);
    if (/email/i.test(col.name) && col.category === 'S') return lit(`${who}+${t.name}${++counter}@example.test`);
    if (col.category === 'S') {
      // Formats agents commonly enforce with CHECK constraints.
      if (/colou?r/i.test(col.name)) return lit('#336699');
      if (/url|website|link|avatar|image/i.test(col.name)) return lit(`https://example.test/${who}-${++counter}`);
      if (/phone|mobile/i.test(col.name)) return lit('+15555550100');
      if (/currency/i.test(col.name)) return lit('USD');
      if (/country/i.test(col.name)) return lit('US');
      if (/locale|lang/i.test(col.name)) return lit('en');
      if (/timezone|time_zone|tz$/i.test(col.name)) return lit('UTC');
      // Lowercase letters, digits and hyphens pass slug, handle and code checks
      // like ^[a-z0-9]+(-[a-z0-9]+)*$ and plain length checks alike.
      return lit(`${who}-${t.name.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}-${++counter}`);
    }
    if (/json/.test(col.type)) return `'{}'`;
    switch (col.category) {
      case 'N': return side === 'A' ? '1' : '2'; // small: fits checks like "rating between 1 and 5"
      case 'B': return 'false';
      case 'D': return 'now()';
      case 'U': return lit(detUuid());
      case 'A': return `'{}'`;
      case 'I': return lit('127.0.0.1');
      default:
        if (/json/.test(col.type)) return `'{}'`;
        if (/interval/.test(col.type)) return `'1 day'`;
        return null; // no idea; the insert will say why
    }
  }

  // Parents before children, so foreign keys have something to point at.
  const order = [];
  const pending = new Set(catalog.map(t => t.name));
  while (pending.size) {
    // Every parent first when possible (an optional link still gets a real
    // parent); optional links are only left empty to break a cycle.
    const strict = [...pending].filter(n => byName.get(n).fks.every(f =>
      f.refSchema !== 'public' || f.refTable === n || !pending.has(f.refTable))
      && (byName.get(n).cfks || []).every(f => f.refSchema !== 'public' || f.refTable === n || !pending.has(f.refTable)));
    const ready = strict.length ? strict : [...pending].filter(n => byName.get(n).fks.every(f =>
      f.refSchema !== 'public' || f.refTable === n || !pending.has(f.refTable)
      || !byName.get(n).columns.find(c => c.name === f.col)?.notNull));
    const next = ready.length ? ready : [[...pending][0]];
    for (const n of next.sort()) { order.push(n); pending.delete(n); }
  }

  // Approval gates: policies that call a helper like is_authorized_user() or
  // is_approved_member(), which checks an allowlist (authorized_users where
  // user_id = auth.uid() and status = 'accepted'). Real users of the app have
  // been let in, so the test users are put on the list the way the app's own
  // invite flow would, with the conditions the helper checks.
  const gates = [];
  const policyText = (await db.query(`select string_agg(coalesce(qual, '') || ' ' || coalesce(with_check, ''), ' ') as t from pg_policies where schemaname = 'public'`)).rows[0]?.t || '';
  const gateFns = (await db.query(`select p.proname as name, p.prosrc as src from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.pronargs = 0 and p.prorettype = 'bool'::regtype`)).rows
    .filter(f => new RegExp(`\\b${f.name}\\s*\\(`, 'i').test(policyText) && /authori[sz]ed|approved|allowed|allowlist|whitelist|invited|member|active|verified|onboarded|beta|access/i.test(f.name) && !/admin|staff|moderator|owner|super|manager/i.test(f.name));
  for (const f of gateFns) {
    const from = f.src.match(/\bfrom\s+(?:public\.)?"?(\w+)"?(?:\s+(?:as\s+)?(?!where|join|inner|left|on\b)(\w+))?/i);
    if (!from || !byName.has(from[1])) continue;
    const T = byName.get(from[1]), alias = from[2];
    const col = c => T.columns.some(x => x.name === c) ? c : null;
    const pre = alias ? `(?:${alias}\\.|${T.name}\\.)?` : `(?:${T.name}\\.)?`;
    const userCol = [...f.src.matchAll(new RegExp(`${pre}(\\w+)\\s*=\\s*\\(?\\s*(?:select\\s+)?auth\\.uid\\(\\)`, 'gi'))].map(m => col(m[1])).find(Boolean)
      || [...f.src.matchAll(new RegExp(`auth\\.uid\\(\\)\\s*\\)?\\s*=\\s*${pre}(\\w+)`, 'gi'))].map(m => col(m[1])).find(Boolean);
    if (!userCol) continue;
    const fixed = Object.fromEntries([...f.src.matchAll(new RegExp(`${pre}(\\w+)\\s*=\\s*('(?:[^']|'')*'|true|false)`, 'gi'))].filter(m => col(m[1]) && m[1] !== userCol).map(m => [m[1], m[2]]));
    for (const m of f.src.matchAll(new RegExp(`${pre}(\\w+)\\s+is\\s+(true|not\\s+null)`, 'gi'))) if (col(m[1]) && m[1] !== userCol) fixed[m[1]] = /true/i.test(m[2]) ? 'true' : null;
    gates.push({ fn: f.name, table: T.name, userCol, fixed });
  }
  const gated = new Set();
  for (const g of gates) {
    if (gated.has(g.table)) continue;
    gated.add(g.table);
    const T = byName.get(g.table);
    // C is the "just signed up" user of the new-user checks: invited ahead of
    // signup, as the app's invite flow does.
    for (const side of ['A', 'B', 'C']) {
      const values = {};
      let ok = true;
      for (const c of T.columns) {
        if (c.name === g.userCol) { values[c.name] = lit(IDS[side]); continue; }
        if (c.name in g.fixed && g.fixed[c.name] !== null) { values[c.name] = g.fixed[c.name]; continue; }
        const v = await valueFor(T, c, side, false);
        if (v === undefined) { if (c.name in g.fixed && c.category === 'D') values[c.name] = 'now()'; continue; }
        if (v === null) { ok = false; break; }
        values[c.name] = v;
      }
      if (!ok) continue;
      const cols = Object.keys(values);
      const sql = `insert into public.${q(g.table)} (${cols.map(q).join(', ')}) values (${cols.map(c => values[c]).join(', ')})`;
      if (db.nested) await db.exec('savepoint vc_gate');
      try {
        await db.exec(`set session_replication_role = replica; ${sql}; set session_replication_role = origin;`);
        emitted.push(`set session_replication_role = replica;\n${sql};\nset session_replication_role = origin;`);
        if (db.nested) await db.exec('release savepoint vc_gate');
      } catch {
        await db.exec('set session_replication_role = origin').catch(() => {});
        if (db.nested) await db.exec('rollback to savepoint vc_gate; release savepoint vc_gate');
      }
    }
    if (await rowCount(g.table) > 0) filled.push(g.table);
  }

  for (const name of order) {
    if (process.env.VC_FX) console.error("FILL", name);
    const t = byName.get(name);
    if (skipCfg[name]?.skip || skipCfg[name]?.noAutoFixtures) { skipped.push(name); continue; }
    // The app's own users table gets a row for each test user even when seed
    // data already fills it: without one they aren't users of the app at all.
    const idt = identity.find(it => it.table === name);
    const haveSide = idt ? Object.fromEntries(await Promise.all(['A', 'B'].map(async sd => [sd, Number((await db.query(`select count(*)::int as n from public.${q(name)} where ${q(idt.authCol)}::text = $1`, [IDS[sd]])).rows[0].n) > 0]))) : null;
    if (idt ? haveSide.A && haveSide.B : await rowCount(name) > 0) continue;
    const isShare = SHARE_TABLE.test(name);
    // A row in "staff" or "admins" makes that user privileged, so a sample row
    // would hand both test users powers the app never gave them.
    // A role column only makes it an ordinary table when it has an unprivileged
    // value to give (user_roles: user/admin). staff_members with roles
    // staff/manager/admin has none: every row in it is a privilege.
    const roleCols = t.columns.filter(c => ROLE_COL.test(c.name) || ADMIN_BOOL_COL.test(c.name));
    // A table whose rows grant roles (user_roles, staff_roles): a row is itself
    // the grant, so an ordinary user has none unless the table has a plainly
    // ordinary role (user, member, customer) to give them.
    const grantTable = /(^|_)roles?$|(^|_)permissions?$|(^|_)grants?$/i.test(name);
    const hasLowRole = roleCols.some(c => { const rv = roleValues(c); return rv && (!grantTable || c.category === 'B' || ORDINARY_ROLE.test(rv.low)); });
    if ((PRIVILEGE_TABLE.test(name) || privilegeTables.has(name) || grantTable) && !hasLowRole) {
      skipped.push(name);
      const values = {};
      let ok = true;
      for (const col of t.columns) {
        const v = await valueFor(t, col, 'B', false);
        if (v === undefined) continue;
        if (v === null) { ok = false; break; }
        values[col.name] = v;
      }
      if (ok && Object.keys(values).some(c => userFkCols(t).includes(c) || USER_COL_NAMES.includes(c))) {
        const cols = Object.keys(values);
        privilegeProbes[name] = `insert into public.${q(name)} (${cols.map(q).join(', ')}) values (${cols.map(c => values[c]).join(', ')})`;
      }
      continue;
    }
    const isMembership = membershipTables.has(name);
    const rows = {};
    for (const side of isShare ? ['B'] : ['A', 'B']) {
      if (haveSide?.[side]) continue;
      const values = {};
      let problem = null;
      for (const col of t.columns) {
        const v = await valueFor(t, col, side, isMembership);
        if (v === undefined) continue;
        if (v === null) { problem = `no value for required column ${col.name}`; break; }
        values[col.name] = v;
      }
      if (problem) { failed.push({ table: name, side, error: problem }); continue; }
      // Multi-column links: take every linked column from one parent row of
      // this side, preferring one that agrees with what's already set (the
      // same team).
      for (const f of (t.cfks || []).filter(f => f.refSchema === 'public' && f.refTable !== name)) {
        const set = f.cols.map((c, i) => [c, f.refCols[i]]).filter(([c]) => values[c] != null && values[c] !== 'null');
        let pr = null;
        if (set.length) {
          const where = set.map(([, rc]) => `${q(rc)}::text = $${set.findIndex(x => x[1] === rc) + 1}`).join(' and ');
          pr = (await tryQuery(`select to_jsonb(x) as r from public.${q(f.refTable)} x where ${where} limit 1`, set.map(([c]) => String(values[c]).replace(/^'|'$/g, '').replace(/''/g, "'")))).rows[0]?.r;
        }
        pr ||= await parentRow(f.refTable, side);
        if (pr && f.refCols.every(rc => pr[rc] != null)) f.cols.forEach((c, i) => { values[c] = lit(pr[f.refCols[i]]); });
      }
      // The table's own format rules (CHECK constraints): shape the sample
      // values to fit them before inserting.
      for (const def of await checksOf(name)) {
        // "a <> b" (you can't follow or challenge yourself): b gets the other
        // test user's value, from the table b points at when it's a link.
        const ne = def.match(/^CHECK \(\(\s*"?(\w+)"?\s*<>\s*"?(\w+)"?\s*\)\)/i);
        let other = lit(IDS[side === 'A' ? 'B' : 'A']);
        const fk = ne && t.fks.find(f => f.col === ne[2] && f.refSchema === 'public');
        if (fk) { const pr = await parentRow(fk.refTable, side === 'A' ? 'B' : 'A'); if (pr?.[fk.refCol] != null) other = lit(pr[fk.refCol]); }
        const seed = (side === 'A' ? 1 : 2) + (counter % 7);
        if (await satisfies(t, def, values)) continue;
        // Try each OR branch on its own and keep the first the database
        // accepts; then small combinations of the values the mentioned columns
        // can take ((a is null) = (b is null), (decision = 'rejected') =
        // (outcome = 'rejected')). The database itself judges every try.
        const colNames = t.columns.map(c => c.name);
        const expr = def.replace(/^CHECK\s*/i, '').replace(/\s+NOT VALID\s*$/i, '');
        let done = false;
        for (const b of splitTopLevel(stripParens(expr), /\s+OR\s+/i)) {
          const trial = fitCheck(`CHECK (${b})`, { ...values }, colNames, other, seed);
          if (await satisfies(t, def, trial)) { Object.assign(values, trial); done = true; break; }
        }
        if (!done) {
          const fitted = fitCheck(def, { ...values }, colNames, other, seed);
          const mentioned = t.columns.filter(c => !c.generated && !c.identity && new RegExp(`(^|[^\\w])"?${c.name}"?([^\\w]|$)`).test(expr)).slice(0, 5);
          const options = mentioned.map(c => [...new Set([values[c.name], fitted[c.name], ...(c.values || []).map(lit),
            ...(c.notNull ? [] : ['null']), ...(c.category === 'D' ? ['now()', `now() + interval '1 day'`] : []), ...(c.category === 'A' ? [...expr.matchAll(/'((?:[^']|'')*)'/g)].slice(0, 2).map(m => `array[${lit(m[1].replace(/''/g, "'"))}]::${c.type}`) : []), ...(c.category === 'B' ? ['true', 'false'] : []),
            ...(c.category === 'U' && /(_by|_id)$/.test(c.name) ? [lit(IDS[side])] : [])].filter(v => v !== undefined))]);
          let tries = 0;
          const walk = async (i, acc) => {
            if (done || tries > 80) return;
            if (i === mentioned.length) {
              tries++;
              const trial = { ...fitted, ...acc };
              for (const [k, v] of Object.entries(trial)) if (v === undefined) delete trial[k];
              if (await satisfies(t, def, trial)) { Object.keys(values).forEach(k => delete values[k]); Object.assign(values, trial); done = true; }
              return;
            }
            for (const v of options[i]) await walk(i + 1, { ...acc, [mentioned[i].name]: v });
          };
          if (mentioned.length) await walk(0, {});
          if (!done) Object.assign(values, fitted);
        }
      }
      // Generated columns are the database's to fill, whatever a rule said.
      for (const c of t.columns) if (c.generated) delete values[c.name];
      const cols = Object.keys(values);
      const overriding = t.columns.some(c => c.identity === 'a' && cols.includes(c.name)) ? ' overriding system value' : '';
      const insert = cols.length
        ? `insert into public.${q(name)} (${cols.map(q).join(', ')})${overriding} values (${cols.map(c => values[c]).join(', ')})`
        : `insert into public.${q(name)} default values`;
      const claims = `select set_config('request.jwt.claims', ${lit(JSON.stringify({ role: 'authenticated', aud: 'authenticated', sub: IDS[side], email: side === 'A' ? 'alice@example.test' : 'bob@example.test', aal: 'aal1', amr: [{ method: 'password', timestamp: 1700000000 }], is_anonymous: false, app_metadata: { provider: 'email', providers: ['email'] } }))}, false)`;
      // In a warm check a failed insert would abort the whole transaction, so
      // each one gets a savepoint.
      if (db.nested) await db.exec('savepoint vc_fixture');
      try {
        await db.exec(`${claims}; `);
        const r = await db.query(`${insert} returning to_jsonb(public.${q(name)}.*) as r`);
        rows[side] = r.rows[0].r;
        emitted.push(`${claims};\n${insert};`);
        if (db.nested) await db.exec('release savepoint vc_fixture');
      } catch (e) {
        if (db.nested) await db.exec('rollback to savepoint vc_fixture; release savepoint vc_fixture');
        // The app's own trigger refused it with a business rule ("you must buy
        // this product before reviewing it"): the sample row is only test data,
        // so insert it with the app's triggers off. Attacks still run with them on.
        let ok = false;
        // Also when the error is about a different table the app's trigger
        // writes (a notification row), not about this sample row itself.
        const otherRel = String(e.message).match(/relation "([^"]+)"/)?.[1];
        if (e.code === 'P0001' || (!e.code && !/violat|permission|policy|does not exist|syntax/i.test(e.message))
          || (otherRel && otherRel !== name && /violates (not-null|check|foreign key) constraint/i.test(e.message))) {
          if (db.nested) await db.exec('savepoint vc_fixture');
          try {
            await db.exec(`${claims}; set session_replication_role = replica;`);
            const r = await db.query(`${insert} returning to_jsonb(public.${q(name)}.*) as r`);
            rows[side] = r.rows[0].r;
            emitted.push(`${claims};\nset session_replication_role = replica;\n${insert};\nset session_replication_role = origin;`);
            ok = true;
            if (db.nested) await db.exec('release savepoint vc_fixture');
          } catch {
            if (db.nested) await db.exec('rollback to savepoint vc_fixture; release savepoint vc_fixture');
          } finally {
            await db.exec('set session_replication_role = origin');
          }
        }
        if (!ok) { failed.push({ table: name, side, error: e.message }); if (process.env.VC_FX) console.error("FXSQL", name, insert.slice(0, 900)); }
      }
    }
    if (rows.A || rows.B) { inserted.set(name, rows); filled.push(name); if (isShare) shareTables.push(name); }
  }
  await db.exec(`select set_config('request.jwt.claims', '', false)`);
  if (emitted.length) emitted.push(`select set_config('request.jwt.claims', '', false);`);
  if (process.env.VC_FX) console.error("FILLED", filled.join(","), "SKIPPED", skipped.join(","));
  if (process.env.VC_FX) for (const f of failed) console.error("FX", f.table, f.side, String(f.error).slice(0, 200));
  return { sql: emitted.join('\n'), filled, failed, skipped, privilegeProbes, shareTables };
}
