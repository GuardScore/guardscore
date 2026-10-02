// The deep check: attack a copy of the app as other people would, and confirm
// its real users still work. Every result carries its own proof (who acted,
// what ran, what happened) and never contains row data, only counts.
import { IDS, runAs } from './db.js';
import { SHARE_TOKEN_COL } from './fixtures.js';

const q = n => `"${n.replace(/"/g, '""')}"`;
const ANON = { role: 'anon' };
// Fields some other party acts on even when only the owner can see the row:
// payment, verification, approval, credits, plan. On an owner-only table these
// still matter (a user marking their own order paid); plain counters/status don't.
const TRUST_FIELD = /(^|_)(paid|payment_status|verified|approved|credits?|balance|plan|tier|subscription(_\w+)?|premium|pro|vip|featured|refunded|wallet|quota|tokens_left)$/i;
// Account entitlements the business grants (a user shouldn't self-verify or
// self-upgrade). On a table only its owner can touch, these still matter, while
// billing facts a user records about themselves (paid, refunded, a balance) do
// not — those flag only where someone else is party to the row.
const ENTITLEMENT = /(^|_)(verified|approved|premium|is_pro|pro|vip|plan|tier|subscription(_\w+)?|role|is_admin|admin)$/i;
const USER_A = { role: 'authenticated', sub: IDS.A };
const USER_B = { role: 'authenticated', sub: IDS.B };
const USER_C = { role: 'authenticated', sub: IDS.C };
const STAFF = { role: 'authenticated', sub: IDS.S };
// A user can edit their own user_metadata in Supabase, so an attacker controls it.
const USER_B_FORGED = { role: 'authenticated', sub: IDS.B, userMeta: { role: 'admin', is_admin: true, admin: true } };

const actorLabel = a => a.role === 'anon' ? 'anonymous visitor'
  : a.sub === IDS.A ? 'user A (the owner)'
  : a.sub === IDS.C ? 'a new user who just signed up'
  : a.sub === IDS.S ? 'a staff member'
  : a.userMeta ? 'user B with self-edited metadata' : 'user B (another user)';

function isAppBug(err) {
  return /more than one row returned by a subquery|is ambiguous|does not exist|cannot be matched|stack depth limit|cannot be nested|must appear in the GROUP BY|operator does not exist|structure of query does not match|query has no destination|control reached end of function|record "[^"]+" (is not assigned|has no field)|invalid reference to FROM-clause|no unique or exclusion constraint matching/i.test(err || '') && !/violates|duplicate key|invalid input/i.test(err || '');
}

function isBlocked(err) {
  return /row-level security|permission denied/i.test(err || '');
}
// A policy that queries its own table makes Postgres stop every query on it.
// Nothing leaks, but the app errors for everyone who touches that table.
const isRecursion = err => /infinite recursion detected in policy/i.test(err || '');
const isDuplicate = err => /duplicate key|unique constraint/i.test(err || '');

// A setup statement that may fail (a trigger refuses the value): in a warm
// check the failure must not abort the surrounding transaction.
async function quietly(db, sql, params = []) {
  if (db.nested) await db.exec('savepoint vc_quiet');
  try { await db.query(sql, params); if (db.nested) await db.exec('release savepoint vc_quiet'); return true; }
  catch { if (db.nested) await db.exec('rollback to savepoint vc_quiet; release savepoint vc_quiet'); return false; }
}

async function templateRow(db, t, key, value) {
  const r = await db.query(`select to_jsonb(x) as r from public.${q(t.name)} x where ${q(key)} = $1 limit 1`, [value]);
  return r.rows[0]?.r || null;
}

// A copied row would collide with the original on unique columns (an invoice
// number, a slug), turning a real result into a duplicate-key error. Give those
// columns fresh values; owner, tenant and foreign-key columns are never touched.
let freshCounter = 0;
function freshenRow(t, row) {
  const out = { ...row };
  for (const c of t.freshen || []) {
    if (out[c.name] == null || c.name === t.owner || c.name === t.tenant || c.name === t.key || c.name === t.role?.col) continue;
    freshCounter++;
    if (c.category === 'S') out[c.name] = `${out[c.name]}-vc${freshCounter}`;
    else if (c.category === 'N') out[c.name] = 900000000 + freshCounter;
    else if (c.category === 'U') out[c.name] = `00000000-0000-4000-8000-e${String(freshCounter).padStart(11, '0')}`;
  }
  return out;
}

function insertSql(t, rawRow) {
  const row = freshenRow(t, rawRow);
  const cols = Object.keys(row).filter(c => !t.generated.includes(c));
  const list = cols.map(q).join(', ');
  return {
    sql: `insert into public.${q(t.name)} (${list}) select ${list} from jsonb_populate_record(null::public.${q(t.name)}, $1::jsonb)`,
    params: [JSON.stringify(Object.fromEntries(cols.map(c => [c, row[c]])))],
  };
}

// kind 'attack': success means a leak. kind 'legit': success means the app works.
// allowed: how many rows the actor may legitimately affect (blind writes touch their own rows too).
// res is { ok, rows?, affected?, n?, error? }: n is set when a remote executor already counted.
export function judgeResult(spec, res) {
  const { id, table, cls, kind, actor, sql, judge, allowed = 0, dependsOn, anyErrorBlocks, duplicateBlocks, noticeIfLeaked } = spec;
  let status;
  let observed;
  if (!res.ok) {
    observed = { error: res.error };
    // Some attacks are stopped by the app's own trigger with its own message
    // ("only admins can change roles"): any error except a duplicate is a block.
    // For a self-granted admin row a duplicate is a block too: the row inserted
    // carries the admin value, so a clash means the admin row was not created
    // (typically a trigger reset the role to one the user already has).
    // A duplicate-key error on an insert means the row got past row level
    // security and only collided with an existing row (B's entry on A's habit
    // for a day A already logged): the write is allowed, and it can block A.
    if (kind === 'attack' && spec.duplicateLeaks && isDuplicate(res.error)) status = 'leaked';
    else if (kind === 'attack') status = isBlocked(res.error) || isRecursion(res.error) || (anyErrorBlocks && (duplicateBlocks || !isDuplicate(res.error))) ? 'blocked' : 'inconclusive';
    else if (spec.duplicateOk && isDuplicate(res.error)) status = 'ok';
    else if (spec.duplicateBreaks && isDuplicate(res.error)) status = 'broken';
    // An app bug (a subquery returning several rows, an ambiguous column) hits
    // real users as well. Constraint errors are usually our sample data's fault,
    // so those stay inconclusive.
    else if (isAppBug(res.error)) status = 'broken';
    else if (spec.bugOnly) status = 'ok';
    // A legit check that errors for any reason other than a duplicate means real
    // users hit that error too (a broken helper function, a policy reading a
    // table they can't read): errorOnly checks count every such error.
    else status = isBlocked(res.error) || isRecursion(res.error) || (spec.errorOnly && !isDuplicate(res.error)) ? 'broken' : 'inconclusive';
  } else {
    const n = res.n !== undefined ? Number(res.n)
      : judge === 'count' ? Number(res.rows[0]?.n ?? 0) : res.affected;
    observed = judge === 'count' ? { rows_visible: n } : { rows_affected: n };
    if (allowed) observed.rows_actor_owns = allowed;
    const happened = n > allowed;
    if (kind === 'attack') status = happened ? 'leaked' : 'blocked';
    // soft: staff may by design see only some rows (reported notes, say), so
    // seeing none isn't broken on its own; losing access a fix took away is.
    else status = happened || spec.errorOnly || spec.soft ? 'ok' : 'broken';
  }
  const out = { id, table, class: cls, kind, status, proof: { actor: actorLabel(actor), sql, observed } };
  if (spec.note && status === 'leaked') out.proof.note = spec.note;
  // A read the app deliberately made public (see publicByDesign): a notice, not a leak.
  if (status === 'leaked' && noticeIfLeaked && !(spec.duplicateLeaks && !res.ok && isDuplicate(res.error))) {
    out.status = 'notice';
    out.class = 'public_by_design';
    out.proof.note = noticeIfLeaked;
  }
  if (dependsOn) out.dependsOn = dependsOn;
  return out;
}

// The executor runs one spec and returns a judged result. Locally it runs on
// PGlite; the remote runner swaps in an executor that records specs instead.
const localExec = db => async spec => judgeResult(spec, await runAs(db, spec.actor, spec.sql, spec.params || [], spec.setup || null, spec.verify || null));

// A check whose prerequisite didn't end in the required status is dropped:
// e.g. the forged-metadata read only means something when the plain read is blocked.
export function applyDependencies(results) {
  const byId = new Map(results.map(r => [r.id, r.status]));
  return results.filter(r => !r.dependsOn || byId.get(r.dependsOn.id) === r.dependsOn.status);
}

// Coverage gaps are reported but never scored: not a pass, not a fail.
function coverageGap(table, reason) {
  return { id: `${table}.coverage`, table, class: 'not_tested', kind: 'coverage', status: 'not_tested', proof: { reason } };
}

// Columns that are harmless to show publicly (a public author profile).
const PUBLIC_PROFILE_COL = /^(id|user_id|profile_id|username|user_name|handle|display_name|name|full_name|first_name|last_name|nickname|bio|about|tagline|avatar|avatar_url|image|image_url|picture|photo_url|website|slug|created_at|updated_at|joined_at|institution|organi[sz]ation|company|job_title|headline|role)$/i;

// A read the app clearly chose to make public: an explicit USING (true) select
// policy on a table with only public-profile columns. Reported as a notice to
// confirm, not a leak; any other column (email, phone, content) stays a leak.
// A read policy that lets everyone see rows the app marked public: USING (true),
// or gated only on a published/public/active/approved flag (optionally OR an
// admin check). What's left after removing those and any is_admin()/role check
// is empty or true — the classic public-catalog / published-content pattern.
const PUBLISH_GATE = /\b(is_)?(published|public|is_public|active|is_active|approved|visible|is_visible|listed|live|available)\b|\b(status|visibility|state)\b\s*(=|in)\s*\(?\s*'(published|public|active|approved|live|listed|visible|available)'/i;
// Replace every EXISTS ( ... ) whose body mentions a published/public/active
// flag with `true`, matching parentheses by hand so nested ()s don't break it.
function stripExistsPublished(text) {
  let out = '', i = 0;
  const low = text.toLowerCase();
  while (i < text.length) {
    const m = low.slice(i).match(/^exists\s*\(/);
    if (m) {
      let depth = 0, j = i + m[0].length - 1;
      for (; j < text.length; j++) { if (text[j] === '(') depth++; else if (text[j] === ')') { depth--; if (depth === 0) { j++; break; } } }
      const body = text.slice(i, j);
      if (/\b(published|is_public|public|is_active|active|approved|visible|listed|live|available)\b/i.test(body)) { out += ' true '; i = j; continue; }
    }
    out += text[i]; i++;
  }
  return out;
}
function publicSelectExpr(text) {
  let e = ` ${String(text || '').trim()} `;
  if (/^\s*\(?\s*true\s*\)?\s*$/i.test(e)) return true;
  // Drop admin/role checks and published-flag comparisons, then see if only
  // boolean glue (and/or/parens/not) remains.
  // A published-content subquery (published lessons of a published course):
  // EXISTS ( select ... where ... published/public/active ) is itself a
  // public-catalog gate. Remove each such EXISTS(...) with a balanced scan.
  e = stripExistsPublished(e);
  e = e.replace(/\b(is_admin|is_staff|is_superadmin|has_role|has_any_role|current_user_role)\s*\([^()]*\)/gi, ' true ')
       .replace(/(\w+\.)?"?\w*(published|public|active|approved|visible|listed|live|available)\w*"?\s*(=\s*true|is\s+true)?/gi, ' true ')
       .replace(/\(?\s*(\w+\.)?"?(status|visibility|state)"?\s*(=|in)\s*\(?\s*'[^']*'(\s*,\s*'[^']*')*\s*\)?\s*\)?/gi, ' true ')
       // Soft-delete / archival filters are part of "show the live public rows".
       .replace(/\(?\s*(not\s+)?(\w+\.)?"?(archived_at|deleted_at|removed_at|is_deleted|is_archived|is_removed|deleted|archived)"?\s*(is\s+(not\s+)?null|=\s*(true|false))?\s*\)?/gi, ' true ');
  const bare = e.replace(/[()]/g, ' ').replace(/\b(true|and|or|not)\b/gi, ' ').trim();
  return bare === '' && PUBLISH_GATE.test(String(text || ''));
}
function publicByDesign(t, byName) {
  const explicit = (t.policies || []).some(p => (p.cmd === 'SELECT' || p.cmd === 'ALL') && publicSelectExpr(p.text));
  if (!explicit) return false;
  if (t.columns.every(c => PUBLIC_PROFILE_COL.test(c))) return true;
  // The author said so in the policy's own name ("Reviews are viewable by
  // everyone"), and nothing personal or secret is in the table: public on
  // purpose. A USING (true) policy named "view their own orders" is the classic
  // mistake, and stays a leak.
  const named = (t.policies || []).some(p => (p.cmd === 'SELECT' || p.cmd === 'ALL') && publicSelectExpr(p.text)
    && /everyone|everybody|public|anyone|anybody|all users|world|visitors|\b(view|see|read|browse|list)s? all\b|^\s*(authenticated|signed[- ]?in|logged[- ]?in|registered) users? (can|may) (view|see|read|browse)\b/i.test(p.policyname || '') && !/\b(own|their|my|self|admins?|staff|moderators?|owners?)\b/i.test(p.policyname || ''));
  if (named && !t.columns.some(c => SENSITIVE_COL.test(c) || SECRET_COL.test(c))) return true;
  // Rows that belong to nobody (a catalog, categories), with an explicit
  // "everyone can read" policy and nothing personal or secret in them: the app
  // clearly means them to be public, so reading them is a notice, not a leak.
  // Ownerless catalog, or content the owner publishes (a review, a public
  // listing) with nothing personal or secret in it: reading it is intended.
  const published = (t.policies || []).some(p => (p.cmd === 'SELECT' || p.cmd === 'ALL') && publicSelectExpr(p.text) && PUBLISH_GATE.test(p.text));
  // A child of a private per-user table (invoice_items under a user's invoices)
  // is not a catalog even without an owner column of its own. A cross-reference
  // to another catalog table (a lesson pointing at its unit) is fine.
  const owns = x => !!x && (x.owner || (x.policies || []).some(p => /(SELECT|ALL)/i.test(p.cmd || 'ALL') && /auth\.uid\(\)\s*\)?\s*=|=\s*\(?\s*(select\s+)?auth\.uid\(\)/i.test(p.text || '')));
  const childOfOwned = byName && (t.fks || []).some(f => f.refSchema === 'public' && f.refTable !== t.name && owns(byName.get(f.refTable)));
  return ((!t.key && !childOfOwned) || published) && !t.columns.some(c => SENSITIVE_COL.test(c) || SECRET_COL.test(c));
}

// Columns that must never be readable by the public, even in a public table.
// Personal data that "readable by every signed-in user" doesn't cover either.
const SENSITIVE_COL = /(^|_)(email|e_mail|phone|mobile|address|street|postcode|postal_code|zip|birth|birthday|dob|date_of_birth|ssn|tax_id|salary|iban|card|ip_address)(_|s$|$)/i;
const SECRET_COL = /(^|_)(token|secret|password|passwd|hash|salt|otp|api_?key|private_?key|session)(_|s$|$)/i;

// A table every visitor may read on purpose: an explicit USING (true) select policy.
const publicSelect = t => (t.policies || []).some(p => (p.cmd === 'SELECT' || p.cmd === 'ALL') && publicSelectExpr(p.text));
const noticeText = t => t.key
  ? `readable by everyone through a USING (true) policy the app names as public, with no personal or secret columns (${t.columns.join(', ')}). Confirm that is intended, and declare it public with a reason.`
  : `readable by everyone through a USING (true) policy, and no row belongs to a user (a catalog?). Confirm that is intended, and declare it public with a reason.`;

export async function gauntlet(db, schema, exec = localExec(db), opts = {}) {
  const only = opts.only || null;
  freshCounter = 0; // same values on every run, so local and remote plans agree
  const check = process.env.VC_TIME ? async (_db, spec) => { const t0 = Date.now(); const r = await exec(spec); const ms = Date.now() - t0; if (ms > 40) console.error(`slow ${ms}ms ${spec.id}`); return r; } : (_db, spec) => exec(spec);
  // Does the app have parties beyond the row's owner — staff, admins, a merchant
  // managing a catalog? If so, money a buyer could set on their own order is the
  // business's; in a purely personal app (a budget, a habit tracker) it isn't.
  const policyText = schema.flatMap(t => (t.policies || []).map(p => p.text || '')).join(' ');
  const multiParty = schema.some(t => t.privilegeProbe || t.role || t.membership)
    || /\bis_staff\b|\bis_admin\b|\bhas_role\b|\bhas_any_role\b|'admin'|'staff'|'merchant'|'seller'|'vendor'/i.test(policyText)
    || schema.some(t => /(^|_)(staff|admins?|merchants?|vendors?|sellers?|employees?|providers?|owners?_table)(_|$)/i.test(t.name));
  // "Every signed-in user can read AND change every row here" — a deliberately
  // shared workspace (an internal team tool) or a multi-tenant leak. We can't
  // tell which without knowing the app has one customer or many, so when the
  // app carries no tenant/org boundary at all we report it as a notice that
  // names the risk, instead of a leak (which would be wrong for the common
  // single-org internal tool) or silence (wrong for a real multi-tenant app).
  const isTrue = x => /^(\s*\(?\s*true\s*\)?\s*)+$/i.test(String(x || '').trim());
  // The app is multi-tenant only when a tenant boundary is actually there to
  // enforce: some policy really scopes rows by a tenant column, a membership
  // function, or a subquery against a membership/group table. A bare
  // tenant-looking FK that no policy uses (a CRM's company_id or sales_id, an
  // entity link) is data, not a customer boundary — so an all-open table in
  // such an app is a shared internal tool, not a cross-tenant leak.
  const TENANT_COL_RE = /(^|[^a-z0-9])(tenant|org|organi[sz]ation|workspace|account|team|company|group|project)_id\b/i;
  const MEMBER_TABLE_RE = /\b(memberships?|team_members?|org(ani[sz]ation)?_members?|workspace_members?|group_members?|project_members?|account_users?|user_(orgs?|organizations?|teams?|workspaces?|accounts?)|collaborators?|participants?)\b/i;
  // Any is_*member() / has_*access() / belongs_to_*() style membership predicate,
  // however the app names it (is_member, is_team_member, is_org_member, ...).
  const MEMBER_FN = /\bis_\w*member\w*\s*\(|\bhas_\w*(access|membership)\s*\(|\bbelongs_to_\w+\s*\(|\bis_(participant|collaborator|authorized_user)\s*\(|current_(org|team|workspace|tenant)\b/i;
  const enforcedTenant = schema.some(t => (t.policies || []).some(p => {
    const txt = p.text || '';
    if (isTrue(txt)) return false;
    return TENANT_COL_RE.test(txt)
      || MEMBER_FN.test(txt)
      || (/\bfrom\s+|\bjoin\s+|\bexists\s*\(/i.test(txt) && MEMBER_TABLE_RE.test(txt));
  }));
  const appHasTenant = enforcedTenant;
  // Does the app use per-user ownership elsewhere? If most tables scope to
  // auth.uid() = <owner>, then a table thrown fully open is an outlier bug
  // (invoice_items left open in a per-user CRM), not a shared workspace — unless
  // its own policy name says the sharing is intended ("Team can view all leads").
  const ownerScoped = t => (t.policies || []).some(p => /(SELECT|ALL)/i.test(p.cmd || 'ALL') && /auth\.uid\(\)\s*\)?\s*=|=\s*\(?\s*(select\s+)?auth\.uid\(\)/i.test(p.text || ''));
  const byName = new Map(schema.map(t => [t.name, t]));
  // A fully-open table that is a CHILD of a per-user-owned table (invoice_items
  // under a user's invoices) is a leak: the app clearly means the parent to be
  // private, so opening the child exposes every owner's rows. A fully-open
  // TOP-LEVEL table (no owned parent) in an app with no tenant boundary is a
  // shared workspace — an internal team tool where the data is shared on purpose.
  // A parent is only "owned" if it is actually scoped to its owner. A parent
  // that has an owner column but is itself readable by everyone (a shared
  // staff/user directory a CRM keys its records to) is not private, so opening
  // its child leaks nothing new.
  const readsOpen = t => (t.policies || []).some(p => (p.cmd === 'SELECT' || p.cmd === 'ALL') && isTrue(p.text) && !/\banon\b/i.test(p.roles || ''));
  const childOfOwned = t => (t.fks || []).some(f => {
    const par = byName.get(f.refTable);
    return f.refSchema === 'public' && f.refTable !== t.name && par && (ownerScoped(par) || par.owner) && !readsOpen(par);
  });
  const fullyOpenShared = t => {
    const pols = t.policies || [];
    const readTrue = pols.some(p => (p.cmd === 'SELECT' || p.cmd === 'ALL') && isTrue(p.text) && !/\banon\b/i.test(p.roles || ''));
    const writeTrue = pols.some(p => (p.cmd === 'UPDATE' || p.cmd === 'DELETE' || p.cmd === 'ALL') && isTrue(p.text) && !/\banon\b/i.test(p.roles || ''));
    return readTrue && writeTrue && !appHasTenant && !childOfOwned(t);
  };
  const anonReadIntended = t => (t.policies || []).some(p => (p.cmd === 'SELECT' || p.cmd === 'ALL')
      && (/\banon\b/i.test(p.roles || '') || /\bpublic\b/i.test(p.roles || '')) && publicSelectExpr(p.text))
    && !(t.columns || []).some(c => SENSITIVE_COL.test(c) || SECRET_COL.test(c));
  const catalogNotice = t => anonReadIntended(t)
    ? `"${t.name}" is opened to anonymous visitors on purpose (a public catalog) and holds no personal or secret columns, so reading it is intended. Confirm nothing private is meant to live here.`
    : undefined;
  const sharedWorkspaceNotice = t => fullyOpenShared(t)
    ? `every signed-in user can read and change all rows in "${t.name}". That is fine for a single-organization internal tool (the whole team shares this data on purpose), but a leak if the app has more than one customer. If it does, scope this table by a tenant/organization the user belongs to.`
    : undefined;
  // A read gated by a membership/roster function (is_authorized_user(),
  // is_member(), is_team_member()): any authorized member can read the rows.
  // On a roster / invitation / team-directory table that is the point — members
  // see each other — so a cross-member read is intended, not a leak. Admin
  // checks are deliberately excluded: those restrict to staff, they don't open
  // a table to every member. Uses the same MEMBER_FN detector as the tenant
  // check above.
  const memberSharedRead = t => !t.publicRead
    && (t.policies || []).some(p => (p.cmd === 'SELECT' || p.cmd === 'ALL') && !/\banon\b/i.test(p.roles || '') && MEMBER_FN.test(p.text || ''));
  const memberRosterNotice = t => memberSharedRead(t)
    ? `every signed-in member can read all rows in "${t.name}" — its read policy allows any authorized member (a team roster, member directory, or shared invitation list). Intended if members are meant to see each other; scope it to the owner if these rows should stay private to each user.`
    : undefined;
  const results = [];
  for (const t of schema) {
    if (only && !only.has(t.name)) continue;
    if (t.skip) continue;
    const T = `public.${q(t.name)}`;
    const key = t.key || null;
    const keyVal = t.keyA;
    const lit = v => `'${String(v).replace(/'/g, "''")}'`;
    const where = key ? `${q(key)} = ${lit(keyVal)}` : 'true';

    // An empty table "blocks" every attack trivially, which proves nothing.
    // Report it as untested instead of letting it count as a pass.
    const rowCount = Number((await db.query(`select count(*)::int as n from ${T}`)).rows[0].n);
    if (rowCount === 0) {
      results.push(coverageGap(t.name, 'table has no sample rows, so it was not tested'));
      continue;
    }

    // Share-link and invitation tables hold only B's shares. Nobody without the
    // link should be able to list them: that turns every secret link public.
    if (t.shareTable) {
      results.push(await check(db, { id: `${t.name}.anon.list_shares`, table: t.name, cls: 'token_enumeration', kind: 'attack',
        actor: ANON, sql: `select count(*) as n from ${T}`, judge: 'count' }));
      results.push(await check(db, { id: `${t.name}.cross.list_shares`, table: t.name, cls: 'token_enumeration', kind: 'attack',
        actor: USER_A, sql: `select count(*) as n from ${T}`, judge: 'count' }));
      // Nobody but the sharer may change or revoke a share (or redirect an invite).
      const touchS = q(t.columns.find(c => !t.generated.includes(c)) || t.columns[0]);
      results.push(await check(db, { id: `${t.name}.anon.update`, table: t.name, cls: 'anon_write', kind: 'attack',
        actor: ANON, sql: `update ${T} set ${touchS} = ${touchS} where true`, judge: 'affected' }));
      results.push(await check(db, { setup: t.deleteSetup, id: `${t.name}.anon.delete`, table: t.name, cls: 'anon_write', kind: 'attack',
        actor: ANON, sql: `delete from ${T} where true`, judge: 'affected' }));
      results.push(await check(db, { id: `${t.name}.cross.update_share`, table: t.name, cls: 'cross_user_write', kind: 'attack',
        actor: USER_A, sql: `update ${T} set ${touchS} = ${touchS} where true`, judge: 'affected' }));
      // Sharing someone else's item: B creates a share for A's private row, then
      // opens it with B's own link.
      const bShare = (await db.query(`select to_jsonb(s.*) as r from ${T} s limit 1`)).rows[0]?.r;
      for (const f of (t.fks || []).filter(f => f.refSchema === 'public' && f.refTable !== t.name)) {
        const parent = schema.find(x => x.name === f.refTable);
        // A link to a person (invited_by -> profiles) names who acted, not an item being shared.
        if (!bShare || !parent?.owner || parent.publicRead || parent.oneRowPerUser) continue;
        const aItem = (await db.query(`select ${q(f.refCol)} as v from public.${q(f.refTable)} where ${q(parent.owner)}::text = $1 limit 1`, [IDS.A])).rows[0]?.v;
        if (aItem == null) continue;
        const row = { ...bShare, [f.col]: aItem };
        for (const c of t.columns.filter(c => SHARE_TOKEN_COL.test(c))) row[c] = typeof bShare[c] === 'string' && /^[0-9a-f-]{36}$/i.test(bShare[c]) ? '00000000-0000-4000-8000-0000000000ee' : `tok-foreign-${t.name}`;
        const ins = insertSql(t, row);
        results.push(await check(db, { id: `${t.name}.cross.share_foreign.${f.col}`, table: t.name, cls: 'share_foreign_item', kind: 'attack',
          actor: USER_B, sql: ins.sql, params: ins.params, judge: 'affected' }));
      }
      // An invitation addressed to A: A (the invitee) must not be able to raise
      // the role it grants before accepting it.
      const roleCol = t.columns.find(c => /^(role|member_role|access_level|permission)$/i.test(c));
      const emailCol = t.columns.find(c => /^(email|invitee_email|invited_email)$/i.test(c));
      if (/invit/i.test(t.name) && roleCol && emailCol) {
        const emailA = (await db.query(`select email from auth.users where id = $1`, [IDS.A])).rows[0]?.email;
        for (const v of ['owner', 'admin']) {
          results.push(await check(db, { id: `${t.name}.invitee.raise_role.${v}`, table: t.name, cls: 'self_grant_admin', kind: 'attack', actor: USER_A,
            setup: `update ${T} set ${q(emailCol)} = '${emailA}'`,
            sql: `with u as (update ${T} set ${q(roleCol)} = '${v}'${t.columns.includes('accepted_by') ? `, accepted_by = auth.uid()` : ''}${t.columns.includes('accepted_at') ? '' : ''} where ${q(emailCol)} = '${emailA}' returning ${q(roleCol)}) select count(*) as n from u where ${q(roleCol)}::text = '${v}'`,
            judge: 'count', anyErrorBlocks: true }));
        }
      }
      // The shared items themselves: anyone may open one with its link, but
      // nobody should be able to list every item that has a link.
      for (const f of (t.fks || []).filter(f => f.refSchema === 'public' && f.refTable !== t.name)) {
        const P = schema.find(x => x.name === f.refTable);
        if (!P || P.publicRead || P.sharedRead || !t.columns.some(c => SHARE_TOKEN_COL.test(c) || /token|code|slug|key/i.test(c))) continue;
        results.push(await check(db, { id: `${P.name}.anon.list_shared_via.${t.name}`, table: P.name, cls: 'token_enumeration', kind: 'attack', actor: ANON,
          // Every row a visitor can list without a token (a policy that shows
          // "any note that has a share row" hands out all of them).
          sql: `select count(*) as n from public.${q(P.name)}${P.columns.some(c => /^(is_)?(public|published|visible|listed)$/i.test(c)) ? ` where not coalesce(${P.columns.filter(c => /^(is_)?(public|published|visible|listed)$/i.test(c)).map(q).join(' or ')}, false)` : ''}`, judge: 'count', anyErrorBlocks: true }));
      }
      // The sharer can still see their own shares (or at least the query works).
      if (!t.serverOnly && t.granted?.read !== false) results.push(await check(db, { id: `${t.name}.legit.read_shares`, table: t.name, cls: 'legit', kind: 'legit',
        actor: USER_B, sql: `select count(*) as n from ${T}`, judge: 'count', errorOnly: true }));
      continue;
    }

    // Anonymous visitors: nobody logged in should read or change private data.
    // With an owner, the target is A's rows: B may have shared B's own on purpose.
    const byDesign = publicByDesign(t, byName) ? noticeText(t) : (catalogNotice(t) || sharedWorkspaceNotice(t));
    if (!t.publicRead) {
      const aRows = t.key ? ` where ${q(t.key)} = '${String(t.keyA).replace(/'/g, "''")}'` : '';
      results.push(await check(db, { id: `${t.name}.anon.read`, table: t.name, cls: 'anon_read', kind: 'attack',
        actor: ANON, sql: `select count(*) as n from ${T}${aRows}`, judge: 'count', noticeIfLeaked: byDesign }));
    }
    // A content row shared by link (B's): listing shared rows without the token
    // exposes every link.
    for (const c of t.columns.filter(c => SHARE_TOKEN_COL.test(c))) {
      results.push(await check(db, { id: `${t.name}.anon.list_shared.${c}`, table: t.name, cls: 'token_enumeration', kind: 'attack',
        actor: ANON, sql: `select count(*) as n from ${T} where ${q(c)} is not null`, judge: 'count' }));
    }
    const touch = q(t.columns.find(c => !t.generated.includes(c)) || t.columns[0]);
    results.push(await check(db, { id: `${t.name}.anon.update`, table: t.name, cls: 'anon_write', kind: 'attack',
      actor: ANON, sql: `update ${T} set ${touch} = ${touch} where true`, judge: 'affected' }));
    results.push(await check(db, { setup: t.deleteSetup, id: `${t.name}.anon.delete`, table: t.name, cls: 'anon_write', kind: 'attack',
      actor: ANON, sql: `delete from ${T} where true`, judge: 'affected' }));

    // Declared public, but holding secrets: declaring a table public doesn't make
    // its share tokens or password hashes safe to hand to everyone.
    const secretCols = t.columns.filter(c => SECRET_COL.test(c));
    const sensitiveCols = t.columns.filter(c => SECRET_COL.test(c) || SENSITIVE_COL.test(c));
    if (t.publicRead && sensitiveCols.length) {
      results.push(await check(db, { id: `${t.name}.anon.read_secrets`, table: t.name,
        cls: secretCols.length ? 'public_secret' : 'declared_sensitive', kind: 'attack',
        actor: ANON, sql: `select count(*) as n from ${T} where ${sensitiveCols.map(c => `${q(c)} is not null`).join(' or ')}`, judge: 'count' }));
    }

    if (!key) {
      // Rows that belong to nobody (a catalog, settings, counters): an ordinary
      // signed-in user must not be able to rewrite or delete them.
      results.push(await check(db, { id: `${t.name}.signed_in.update_any`, table: t.name, cls: 'shared_data_write', kind: 'attack',
        actor: USER_B, sql: `update ${T} set ${touch} = ${touch} where true`, judge: 'affected', noticeIfLeaked: sharedWorkspaceNotice(t) }));
      results.push(await check(db, { setup: t.deleteSetup, id: `${t.name}.signed_in.delete_any`, table: t.name, cls: 'shared_data_write', kind: 'attack',
        actor: USER_B, sql: `delete from ${T} where true`, judge: 'affected', noticeIfLeaked: sharedWorkspaceNotice(t) }));
      // Nothing links these rows to a signed-in user or team, so "another user
      // reads my rows" couldn't be tried. Unless the table is meant to be public,
      // that is a gap, not a pass.
      // Row level security on and no policies at all: no signed-in user can
      // reach any row, so there is no other-user attack left to run.
      // ...or every rule on it is a staff/admin check (an allowlist, an audit
      // log): there is no ordinary user whose rows another could reach.
      const staffOnlyTable = (t.policies || []).length && t.policies.every(p => (/admin|staff|moderator|is_[a-z_]+\s*\(|has_role|service_role/i.test(p.text) || /(^|,)\s*(service_role|supabase_admin)\s*(,|$)/i.test(p.roles || '')) && !/auth\.uid\(\)\s*=|=\s*auth\.uid\(\)/i.test(p.text));
      const serverTable = /(^|_)(stripe|billing|webhooks?|audit|logs?|events?|analytics|cron|jobs?|queues?|sync|integrations?|telemetry|outbox|rate_?(limits?|buckets?)|metrics|stats)(_|$)/i.test(t.name);
      // A shared reference table read by any member (is_member/is_authorized_user)
      // and written only by the service role: every member sees the same shared
      // rows, so there are no per-user rows to leak between users. The write
      // attacks above already proved ordinary users can't change it, so this is a
      // covered, intentionally-shared table, not an untested gap.
      if (memberSharedRead(t)) {
        const n = memberRosterNotice(t);
        if (n) results.push({ id: `${t.name}.shared_reference`, table: t.name, class: 'shared_reference', kind: 'notice', status: 'notice', proof: { note: n } });
      } else if (!t.publicRead && !byDesign && !publicSelect(t) && !(t.rls && !(t.policies || []).length) && !staffOnlyTable && !serverTable) {
        results.push(coverageGap(t.name, 'no column links its rows to a signed-in user (auth.users) or a team, so only the anonymous-visitor attacks ran; other-user attacks could not'));
      }
      continue;
    }

    let tpl = await templateRow(db, t, key, keyVal);
    if (!tpl) {
      results.push(coverageGap(t.name, `no sample row belongs to user A (${key}), so cross-user checks were not run`));
      continue;
    }

    // Another logged-in user (in another tenant, if tenants exist).
    if (!t.publicRead && !t.sharedRead) {
      const read = await check(db, { id: `${t.name}.cross.read`, table: t.name, cls: t.keyKind === 'tenant' ? 'cross_tenant_read' : 'cross_user_read',
        kind: 'attack', actor: USER_B, sql: `select count(*) as n from ${T} where ${where}`, judge: 'count', noticeIfLeaked: byDesign || memberRosterNotice(t) });
      results.push(read);
      results.push(await check(db, { id: `${t.name}.forged_meta.read`, table: t.name, cls: 'trusts_user_metadata',
        kind: 'attack', actor: USER_B_FORGED, sql: `select count(*) as n from ${T} where ${where}`, judge: 'count',
        dependsOn: { id: `${t.name}.cross.read`, status: 'blocked' } }));
    }
    // Rows change state: a policy like "user_id = auth.uid() or deleted_at is
    // not null" hides A's rows only until A deletes (or archives, or completes)
    // one. Flip that state on A's rows and try the reads again.
    if (!t.publicRead && !t.sharedRead) {
      for (const c of (t.stateCols || []).slice(0, 3)) {
        const setup = `update ${T} set ${q(c.name)} = ${c.bool ? 'true' : 'now()'} where ${where}`;
        for (const [actor, who, cls] of [[ANON, 'anon', 'anon_read'], [USER_B, 'cross', t.keyKind === 'tenant' ? 'cross_tenant_read' : 'cross_user_read']]) {
          results.push(await check(db, { id: `${t.name}.state.${c.name}.${who}.read`, table: t.name, cls, kind: 'attack', actor, setup,
            sql: `select count(*) as n from ${T} where ${where}`, judge: 'count', noticeIfLeaked: byDesign }));
        }
      }
    }
    results.push(await check(db, { id: `${t.name}.cross.update`, table: t.name, cls: 'cross_user_write', kind: 'attack',
      actor: USER_B, sql: `update ${T} set ${q(key)} = ${q(key)} where ${where}`, judge: 'affected', noticeIfLeaked: sharedWorkspaceNotice(t) }));
    results.push(await check(db, { setup: t.deleteSetup, id: `${t.name}.cross.delete`, table: t.name, cls: 'cross_user_write', kind: 'attack',
      actor: USER_B, sql: `delete from ${T} where ${where}`, judge: 'affected', noticeIfLeaked: sharedWorkspaceNotice(t) }));

    // Blind writes: an UPDATE or DELETE that never reads a column is checked only
    // against the UPDATE/DELETE policies, not SELECT. A broken write policy lets
    // user B rewrite everyone's rows even when B can't see them.
    const keyValB = t.keyB;
    const ownB = keyValB == null ? 0 : Number((await db.query(`select count(*)::int as n from ${T} where ${q(key)}::text = $1`, [String(keyValB)])).rows[0].n);
    const setCol = t.columns.find(c => c !== key && c !== t.owner && c !== t.tenant && !t.generated.includes(c));
    if (tpl && setCol) {
      results.push(await check(db, { id: `${t.name}.cross.blind_update`, table: t.name, cls: 'cross_user_write', kind: 'attack',
        actor: USER_B, sql: `update ${T} set ${q(setCol)} = (jsonb_populate_record(null::${T}, $1::jsonb)).${q(setCol)}`,
        params: [JSON.stringify({ [setCol]: tpl[setCol] })], judge: 'affected', allowed: ownB, noticeIfLeaked: sharedWorkspaceNotice(t) }));
    }
    results.push(await check(db, { setup: t.deleteSetup, id: `${t.name}.cross.blind_delete`, table: t.name, cls: 'cross_user_write', kind: 'attack',
      actor: USER_B, sql: `delete from ${T}`, judge: 'affected', allowed: ownB, noticeIfLeaked: sharedWorkspaceNotice(t) }));

    if (tpl) {
      // User B writes a row that claims to belong to user A (or A's tenant).
      const forged = { ...tpl };
      if (t.owner) forged[t.owner] = IDS.A;
      if (t.tenant) forged[t.tenant] = t.tenantA;
      if (t.keyKind === 'parent') forged[key] = t.keyA;
      const ins = insertSql(t, forged);
      // If the key is a generated id (a team's own id), a new row is just a new
      // team, not a row claiming to be someone else's.
      // Counted by where the row landed: a trigger that stamps the caller's own
      // account on every insert defeats the forgery even if the insert succeeds.
      const landed = { sql: `select count(*)::int as n from public.${q(t.name)} where ${q(key)}::text = $1`, params: [String(t.keyA)] };
      if (!t.generated.includes(key)) results.push(await check(db, { id: `${t.name}.cross.insert_as_other`, table: t.name, cls: 'impersonated_insert',
        kind: 'attack', actor: USER_B, sql: ins.sql, params: ins.params, judge: 'affected', verify: landed, noticeIfLeaked: sharedWorkspaceNotice(t) }));
      const anonIns = await check(db, { id: `${t.name}.anon.insert`, table: t.name, cls: 'anon_write', kind: 'attack',
        actor: ANON, sql: ins.sql, params: ins.params, judge: 'affected' });
      results.push(anonIns);

      // B attaches a row of B's own to A's private item (a check-in on A's habit,
      // a task in A's project): it shows up in A's data, or blocks A's own row.
      const bOwn = t.owner ? await templateRow(db, t, t.owner, IDS.B) : null;
      if (bOwn && !t.membership && !t.shareTable) {
        for (const f of (t.fks || []).filter(f => f.refSchema === 'public' && f.refTable !== t.name && ![t.owner, t.tenant].includes(f.col))) {
          const P = schema.find(x => x.name === f.refTable);
          if (!P?.owner || P.publicRead || P.sharedRead || P.oneRowPerUser) continue;
          const aItem = (await db.query(`select ${q(f.refCol)}::text as v from public.${q(P.name)} where ${q(P.owner)}::text = $1 limit 1`, [IDS.A])).rows[0]?.v;
          if (aItem == null || String(bOwn[f.col]) === aItem) continue;
          const ins = insertSql(t, { ...bOwn, [f.col]: aItem });
          // A random id is only a secret while nobody else can see it. If B can
          // read A's item id anywhere (another table that references it, a
          // shared row), B can attach to it: that's a leak, not a notice.
          const isUuid = /^[0-9a-f-]{36}$/i.test(aItem);
          let seenIn = null;
          if (isUuid) for (const x of schema.filter(x => x.name !== P.name && !x.skipCheck)) {
            const r = await runAs(db, USER_B, `select count(*)::int as n from public.${q(x.name)} r where strpos(r::text, $1) > 0`, [aItem]);
            if (r.ok && Number(r.rows[0]?.n) > 0) { seenIn = x.name; break; }
          }
          // Only B ever sees B's own row here (owner-only rules), the link isn't
          // unique so a collision can't block A, and A's item id shows up
          // nowhere B can read: attaching to it shows A nothing and takes
          // nothing from A. It only confirms the id exists, so skip it.
          const fkUnique = (t.uniques || []).some(u => u.includes(f.col) && !u.includes(t.owner));
          if (t.ownerOnly && !fkUnique && !seenIn) continue;
          results.push(await check(db, { id: `${t.name}.cross.attach_to_other.${f.col}`, table: t.name, cls: 'foreign_parent_write', kind: 'attack',
            actor: USER_B, sql: ins.sql, params: ins.params, judge: 'affected', anyErrorBlocks: true, duplicateLeaks: !/^[0-9a-f-]{36}$/i.test(aItem),
            // With random ids (uuids) this needs an id B can't guess, so it's a
            // weakness; with sequential ids (1, 2, 3) B can reach every user's
            // items, and a collision can stop A logging their own.
            ...(seenIn ? { note: `B can read A's ${P.name} id in "${seenIn}"` } : {}),
            noticeIfLeaked: isUuid && !seenIn ? `user B can attach rows to another user's ${P.name} if B learns its id; tighten the insert rule so "${f.col}" must point at the author's own ${P.name}` : undefined }));
        }
        // A value unique across the whole table (an invoice number) that each
        // user picks for themselves: the second user to pick it gets an error.
        for (const u of (t.uniques || []).filter(u => u.length === 1 && ![t.owner, t.tenant, key].includes(u[0]) && !t.generated.includes(u[0])
          && /(^|_)(number|no|code|ref|reference|sku|title|name)$/i.test(u[0]) && !/email|user_?name|handle|slug|domain|phone/i.test(u[0]))) {
          const c = u[0];
          if (typeof tpl[c] !== 'string') continue;
          const ins = insertSql(t, bOwn);
          const obj = JSON.parse(ins.params[0]); obj[c] = tpl[c];
          results.push(await check(db, { id: `${t.name}.legit.per_user_unique.${c}`, table: t.name, cls: 'legit', kind: 'legit',
            actor: USER_B, sql: ins.sql, params: [JSON.stringify(obj)], judge: 'affected', duplicateBreaks: true }));
        }
      }

      // Membership tables: can user B add themselves to A's tenant?
      if (t.membership && t.owner && t.tenant) {
        const join = { ...tpl, [t.owner]: IDS.B, [t.tenant]: t.tenantA };
        const j = insertSql(t, join);
        results.push(await check(db, { id: `${t.name}.self_join_other_tenant`, table: t.name, cls: 'tenant_self_join',
          kind: 'attack', actor: USER_B, sql: j.sql, params: j.params, judge: 'affected' }));
      }
    }

    // The legitimate owner must still be able to use the app.
    const ops = t.tenantPlaceholder && ['tenant', 'parent'].includes(t.keyKind) ? [] : t.legitOps;
    if (ops.includes('read')) {
      let readOwn = await check(db, { id: `${t.name}.legit.read_own`, table: t.name, cls: 'legit', kind: 'legit',
        actor: USER_A, sql: `select count(*) as n from ${T} where ${where}`, judge: 'count' });
      // A's sample row may just be the wrong kind of row (a message in a
      // channel A isn't in, a draft only staff see). Before calling the app
      // broken, try the other values the read rules distinguish on; if one
      // works for A, keep it and carry on with that row.
      if (readOwn.status === 'broken' && !readOwn.proof?.observed?.error) {
        const polText = (t.policies || []).filter(p => /SELECT|ALL/i.test(p.cmd || 'ALL')).map(p => p.text).join(' ');
        const variants = [];
        for (const c of (t.variantCols || [])) {
          if (!new RegExp(`(^|[^\\w])"?${c.name}"?([^\\w]|$)`).test(polText)) continue;
          for (const v of c.values) variants.push([c.name, v]);
        }
        for (const [col, v] of variants.slice(0, 24)) {
          const prev = (await db.query(`select ${q(col)}::text as v from ${T} where ${where} limit 1`)).rows[0]?.v;
          if (!await quietly(db, `update ${T} set ${q(col)} = $1 where ${where}`, [v])) {
            // A rule tying this column to others ("action" messages need a
            // conversation, the rest must not have one): clear the optional
            // columns that rule mentions and try once more.
            const defs = (await db.query(`select pg_get_constraintdef(oid) as d from pg_constraint where conrelid = $1::regclass and contype = 'c'`, [`public.${q(t.name)}`])).rows.map(r => r.d).filter(d => new RegExp(`\\b${col}\\b`).test(d));
            const clear = (t.nullableCols || []).filter(n => n !== col && n !== key && defs.some(d => new RegExp(`\\b${n}\\b`).test(d)));
            if (!clear.length || !await quietly(db, `update ${T} set ${q(col)} = $1, ${clear.map(n => `${q(n)} = null`).join(', ')} where ${where}`, [v])) continue;
          }
          const again = await check(db, { id: `${t.name}.legit.read_own`, table: t.name, cls: 'legit', kind: 'legit',
            actor: USER_A, sql: `select count(*) as n from ${T} where ${where}`, judge: 'count' });
          if (again.status !== 'broken') { readOwn = again; tpl = await templateRow(db, t, key, keyVal) || tpl; break; }
          await quietly(db, `update ${T} set ${q(col)} = $1 where ${where}`, [prev]);
        }
      }
      results.push(readOwn);
      // The app's own list query has no filter: every policy branch runs for
      // every row, so an error in a helper (ambiguous column, a table users
      // can't read) shows up here and not in the filtered read.
      results.push(await check(db, { id: `${t.name}.legit.list`, table: t.name, cls: 'legit', kind: 'legit',
        actor: USER_A, sql: `select count(*) as n from ${T}`, judge: 'count', errorOnly: true }));
    }
    // One row per user (a profile): a new user must end up with one, either
    // from a signup trigger or by creating it. With neither, nobody new can use
    // anything that needs it.
    if (t.oneRowPerUser && t.owner && !t.serverOnly && ops.some(o => o !== 'read') && !t.role && !t.membership && !t.privilegeProbe && tpl && !/admin|staff|moderator|superuser|operator|role/i.test(t.name)) {
      const row = { ...tpl, [t.owner]: IDS.C };
      for (const u of (t.uniques || []).filter(u => u.length === 1 && u[0] !== t.owner)) {
        const c = u[0];
        if (typeof row[c] === 'string') row[c] = /email/i.test(c) ? `carol-${c}@example.test` : `carol-${c}-${t.name}`;
        else if (typeof row[c] === 'number') row[c] = 900001;
      }
      const ins = insertSql(t, row);
      const inline = ins.sql.replace('$1::jsonb', `'${ins.params[0].replace(/'/g, "''")}'::jsonb`);
      const T2 = `public.${q(t.name)}`;
      // Signing up (as the server would) may already create the row through a
      // trigger; otherwise the new user has to be able to create it.
      const setup = [
        `insert into auth.users (id, email) values ('${IDS.C}', 'carol@example.test') on conflict do nothing;`,
        `create function public.vc_row_exists_c() returns boolean language sql security definer as $f$ select exists (select 1 from ${T2} where ${q(t.owner)}::text = '${IDS.C}') $f$;`,
        `create function public.vc_new_user_row() returns bigint language plpgsql security invoker as $f$ begin if public.vc_row_exists_c() then return 1; end if; ${inline}; return 1; end $f$;`,
        `grant execute on function public.vc_row_exists_c(), public.vc_new_user_row() to authenticated;`].join(' ');
      // The email on a profile is the user's own: a new user must not be able
      // to claim someone else's address (which also blocks the real owner when
      // the column is unique).
      const emailCol = t.columns.find(c => /^(email|email_address|contact_email)$/i.test(c));
      if (emailCol) {
        const spoof = { ...row, [emailCol]: 'victim@elsewhere.test' };
        const si = insertSql(t, spoof);
        results.push(await check(db, { id: `${t.name}.new_user.claims_other_email`, table: t.name, cls: 'impersonated_insert', kind: 'attack',
          setup: `insert into auth.users (id, email) values ('${IDS.C}', 'carol@example.test') on conflict do nothing; delete from ${T2} where ${q(t.owner)}::text = '${IDS.C}'`,
          actor: USER_C, sql: `with i as (${si.sql} returning ${q(emailCol)}) select count(*) as n from i where ${q(emailCol)} = 'victim@elsewhere.test'`, params: si.params, judge: 'count', anyErrorBlocks: true,
          // With a unique email column this takes the address away from its
          // owner (their own signup then fails); otherwise it's a weaker
          // impersonation risk, reported as a notice.
          noticeIfLeaked: (t.uniques || []).some(u => u.length === 1 && u[0] === emailCol) ? undefined
            : `a new user can put any email address in "${emailCol}"; bind it to the sign-in email (auth.jwt() ->> 'email') if other people rely on it` }));
      }
      results.push(await check(db, { id: `${t.name}.legit.new_user_row`, table: t.name, cls: 'legit', kind: 'legit', setup,
        actor: USER_C, sql: `select public.vc_new_user_row() as n`, judge: 'count', duplicateOk: true }));
    }
    if (ops.includes('insert') && tpl) {
      // Like the app would: leave out what the database fills in (defaults,
      // flags a trigger set on the sample row), keep the row's owner and key.
      const fresh = Object.fromEntries(Object.entries(tpl).filter(([c]) => !(t.defaulted || []).includes(c) || [key, t.owner, t.tenant].includes(c)));
      const ins = insertSql(t, fresh);
      results.push(await check(db, { id: `${t.name}.legit.insert_own`, table: t.name, cls: 'legit', kind: 'legit',
        actor: USER_A, sql: ins.sql, params: ins.params, judge: 'affected' }));
    }
    if (ops.includes('update')) {
      results.push(await check(db, { id: `${t.name}.legit.update_own`, table: t.name, cls: 'legit', kind: 'legit',
        actor: USER_A, sql: `update ${T} set ${q(t.updateCol || key)} = ${q(t.updateCol || key)} where ${where}`, judge: 'affected' }));
    }
    if (ops.includes('delete')) {
      results.push(await check(db, { setup: t.deleteSetup, id: `${t.name}.legit.delete_own`, table: t.name, cls: 'legit', kind: 'legit',
        actor: USER_A, sql: `delete from ${T} where ${where}`, judge: 'affected' }));
    }
    // Published rows stay visible: when a read policy is written around a
    // "published"/"public" flag, B's published row must be readable by anyone.
    // A "shared" flag next to a share token means shared by secret link, not
    // published: those rows are reached by token, not browsed.
    const linkShared = t.columns.some(c => /(share|access|invite|public)_?(token|code|key|slug|id)$|^token$/i.test(c) && c !== key);
    for (const c of t.columns.filter(c => /^(is_)?(public|published|shared|visible|listed)$/i.test(c) && !(linkShared && /shared/i.test(c)))) {
      const mentions = (t.policies || []).some(p => (p.cmd === 'SELECT' || p.cmd === 'ALL') && new RegExp(`\\b${c}\\b`).test(p.text));
      if (!mentions || t.keyB == null) continue;
      const bPub = Number((await db.query(`select count(*)::int as n from ${T} where ${q(key)}::text = $1 and ${q(c)} is true`, [String(t.keyB)])).rows[0].n);
      if (!bPub) continue;
      results.push(await check(db, { id: `${t.name}.legit.published_visible.${c}`, table: t.name, cls: 'legit', kind: 'legit', actor: USER_A,
        sql: `select count(*) as n from ${T} where ${q(key)}::text = '${String(t.keyB).replace(/'/g, "''")}' and ${q(c)} is true`, judge: 'count' }));
    }
    if (t.publicRead) {
      results.push(await check(db, { id: `${t.name}.legit.public_read`, table: t.name, cls: 'legit', kind: 'legit',
        actor: ANON, sql: `select count(*) as n from ${T}`, judge: 'count' }));
    }

    // Declared readable by every signed-in user, but holding personal data or
    // secrets of other users: the declaration doesn't cover those columns.
    if (t.sharedRead && !t.publicRead && sensitiveCols.length && key) {
      results.push(await check(db, { id: `${t.name}.cross.read_sensitive`, table: t.name, cls: 'declared_sensitive', kind: 'attack',
        actor: USER_B, sql: `select count(*) as n from ${T} where ${where} and (${sensitiveCols.map(c => `${q(c)} is not null`).join(' or ')})`, judge: 'count' }));
    }

    // Tampering: B sets money or status columns on B's own row (order marked
    // paid, price 0, credits topped up) where staff or admins manage those rows.
    if (t.tamper?.length && t.owner) {
      const bRow = await templateRow(db, t, t.owner, IDS.B);
      if (bRow) {
        for (const { col, value: v0, kind } of t.tamper) {
          // On a table only its owner can see or touch, a plain counter or
          // status is the owner's own business (a personal CRM's deal stage, a
          // habit tally). Money, paid/verified marks and credits still matter —
          // a user marking their own order paid or crediting their own wallet.
          // On a table only its owner can see or touch (a personal budget, a
          // habit tracker), a counter, a status, a money amount or a numeric
          // balance is the owner's own data. A boolean entitlement flag
          // (is_premium, paid, verified, approved) is still the business's to
          // set, so it stays flagged even here.
          if (t.ownerOnly && !ENTITLEMENT.test(col) && !(kind === "money" && multiParty)) continue;
          // Already at the tampered value (a total that starts at 0): use another.
          const same = bRow[col] != null && Number.isFinite(Number(bRow[col])) && Number(bRow[col]) === Number(v0);
          const value = same && kind === 'money' ? '0.01' : same && kind === 'counter' ? '12345' : v0;
          if (bRow[col] != null && String(bRow[col]) === value) continue;
          const C = q(col);
          results.push(await check(db, { id: `${t.name}.tamper.${col}`, table: t.name, cls: 'privileged_tamper', kind: 'attack',
            actor: USER_B, sql: `with u as (update ${T} set ${C} = $1 where ${q(t.owner)} = '${IDS.B}' returning ${C}) select count(*) as n from u where ${kind === 'money' || kind === 'counter' ? `${C}::numeric = $2::numeric` : `${C}::text = $2`}`,
            params: [value, value], judge: 'count', anyErrorBlocks: true }));
        }
        // The same fields set when the row is created: an order inserted as
        // "delivered", a review created with verified_purchase already true.
        // (Work items like tasks can start in any status; only counters and
        // buyer-side records are the business's to set.)
        for (const { col, value, kind } of t.tamper.filter(x => (!t.ownerOnly || ENTITLEMENT.test(x.col) || (x.kind === "money" && multiParty)) && (x.kind === 'counter' || (x.kind === 'status' && /order|payment|subscription|checkout|cart/i.test(t.name))))) {
          const row = { ...bRow, [col]: value };
          const ins = insertSql(t, row);
          results.push(await check(db, { id: `${t.name}.tamper_insert.${col}`, table: t.name, cls: 'privileged_tamper', kind: 'attack', actor: USER_B,
            sql: `with i as (${ins.sql} returning ${q(col)}) select count(*) as n from i where ${kind === 'counter' ? `${q(col)}::numeric = $2::numeric` : `${q(col)}::text = $2`}`, params: [ins.params[0], value], judge: 'count', anyErrorBlocks: true, duplicateBlocks: false }));
        }
      }
    }

    // Negative amounts: B sets a quantity or amount on B's own order or cart
    // row below zero. Accepted, it turns a purchase into a refund.
    // Buyer-side tables only: a freelancer's own invoice may well be a credit note.
    // And only in a shop: a household ledger or budget app's "payments" are the
    // user's own records, where a negative entry is a refund they typed in.
    // Wallets and credits are always the business's balance.
    const shop = schema.some(x => /(^|_)(products?|prices?|plans?|skus?|inventory|stripe|merchants?|sellers?|vendors?|stores?|shops?|listings?|catalog|menu_items?|coupons?)(_|$)/i.test(x.name));
    if (!t.ownerOnly && (/wallet|credit/i.test(t.name) || (shop && /order|cart|basket|checkout|payment/i.test(t.name))) && t.keyB != null) {
      const numCols = (t.numeric || []).filter(c => /^(quantity|qty|amount|price|unit_price|total|total_amount|total_price|subtotal|credits?|balance)$/i.test(c) && ![key, t.owner, t.tenant].includes(c));
      for (const c of numCols.slice(0, 2)) {
        const C = q(c);
        results.push(await check(db, { id: `${t.name}.negative.${c}`, table: t.name, cls: 'negative_value', kind: 'attack', actor: USER_B,
          sql: `with u as (update ${T} set ${C} = -100 where ${q(key)}::text = '${String(t.keyB).replace(/'/g, "''")}' returning ${C}) select count(*) as n from u where ${C} < 0`,
          judge: 'count', anyErrorBlocks: true }));
      }
    }

    // Team self-promotion: B, an ordinary member of A's team (set up as the
    // server would after an invite), raises their own role.
    if (t.membership && t.memberRole && t.owner && t.tenant) {
      const bRow = await templateRow(db, t, t.owner, IDS.B);
      if (bRow) {
        const R = q(t.memberRole.col);
        const row = { ...bRow, [t.tenant]: t.tenantA, [t.memberRole.col]: t.memberRole.low };
        const cols = Object.keys(row).filter(c => !t.generated.includes(c));
        const lit = v => `'${String(v).replace(/'/g, "''")}'`;
        const setup = `insert into ${T} (${cols.map(q).join(', ')}) select ${cols.map(q).join(', ')} from jsonb_populate_record(null::${T}, ${lit(JSON.stringify(Object.fromEntries(cols.map(c => [c, row[c]]))))}::jsonb)`;
        results.push(await check(db, { id: `${t.name}.self_promote`, table: t.name, cls: 'team_self_promotion', kind: 'attack', actor: USER_B, setup,
          sql: `with u as (update ${T} set ${R} = $1 where ${q(t.owner)} = '${IDS.B}' and ${q(t.tenant)} = ${lit(t.tenantA)} returning ${R}) select count(*) as n from u where ${R}::text = $2`,
          params: [t.memberRole.admin, t.memberRole.admin], judge: 'count', anyErrorBlocks: true }));
      }
    }

    // Self-granted admin: a role column the access rules rely on, that user B
    // sets on their own row (or inserts a new row with). Success is judged on
    // the value actually stored, so a trigger that quietly resets it counts as blocked.
    if (t.role && t.owner) {
      const R = q(t.role.col);
      const bRow = await templateRow(db, t, t.owner, IDS.B);
      if (bRow) {
        results.push(await check(db, { id: `${t.name}.self_grant_admin.update`, table: t.name, cls: 'self_grant_admin', kind: 'attack',
          actor: USER_B, sql: `with u as (update ${T} set ${R} = $1 where ${q(t.owner)} = '${IDS.B}' returning ${R}) select count(*) as n from u where ${R}::text = $2`,
          params: [t.role.admin, t.role.admin], judge: 'count', anyErrorBlocks: true }));
      }
      if (t.role.insertable && (bRow || tpl)) {
        const row = { ...(bRow || tpl), [t.owner]: IDS.B, [t.role.col]: t.role.admin };
        const ins = insertSql(t, row);
        results.push(await check(db, { id: `${t.name}.self_grant_admin.insert`, table: t.name, cls: 'self_grant_admin', kind: 'attack',
          actor: USER_B, sql: `with i as (${ins.sql} returning ${R}) select count(*) as n from i where ${R}::text = $2`,
          params: [ins.params[0], t.role.admin], judge: 'count', anyErrorBlocks: true, duplicateBlocks: true }));
      }
    }
  }

  // Functions that run with their owner's rights (security definer) skip row
  // level security. Call each one a visitor or user B may execute, passing user
  // A's identifiers, and look for A's private values in what comes back.
  const statusNow = new Map(results.map(r => [r.id, r.status]));
  const isPrivate = t => !t.publicRead && !t.sharedRead && (statusNow.get(`${t.name}.anon.read`) === 'blocked' || statusNow.get(`${t.name}.cross.read`) === 'blocked');
  const markers = new Set();
  const aIds = new Set([IDS.A]);
  const idsByTable = {};
  // Personal identifiers of A that an attacker could plausibly know or guess
  // (email, phone) — used to catch functions that hand back someone's private
  // data when keyed on such an identifier.
  const personalKeys = new Set();
  for (const t of schema.filter(x => x.key && isPrivate(x))) {
    const rows = (await db.query(`select to_jsonb(x) as r from public.${q(t.name)} x where ${q(t.key)}::text = $1`, [String(t.keyA)])).rows;
    for (const { r } of rows) for (const [c, v] of Object.entries(r)) {
      if (typeof v === 'string' && v.length >= 8 && /alice/i.test(v)) markers.add(v);
      if (typeof v === 'string' && /^[0-9a-f-]{36}$/.test(v) && c !== t.key) { aIds.add(v); (idsByTable[t.name] ||= new Set()).add(v); }
      if (typeof v === 'string' && /(phone|mobile|whatsapp|contact|msisdn|tel)/i.test(c) && /\d{6,}/.test(v)) { markers.add(v); personalKeys.add(v); }
      if (typeof v === 'string' && /email/i.test(c) && v.includes('@')) personalKeys.add(v);
    }
  }
  const emailA = (await db.query(`select email from auth.users where id = $1`, [IDS.A])).rows[0]?.email;
  if (emailA) { markers.add(emailA); personalKeys.add(emailA); }
  const fns = markers.size ? (await db.query(`
    select p.oid::regprocedure::text as sig, p.proname as name,
      coalesce((select array_agg(format_type(t, null) order by i) from unnest(p.proargtypes) with ordinality a(t, i)), '{}') as args,
      format_type(p.prorettype, null) as returns,
      has_function_privilege('anon', p.oid, 'EXECUTE') as anon_can,
      has_function_privilege('authenticated', p.oid, 'EXECUTE') as auth_can
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.prosecdef and p.prokind = 'f'
      and format_type(p.prorettype, null) not in ('trigger', 'event_trigger', 'boolean', 'void')
      and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')`)).rows : [];
  const esc = v => `'${String(v).replace(/'/g, "''")}'`;
  const reEsc = m => m.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // A value only proves a leak if the attack didn't pass it in: a function that
  // echoes the email it was given reveals nothing, one that answers with A's
  // account id for that email does.
  for (const f of fns) {
    // A function the app named public and granted to anonymous visitors on
    // purpose (public_pricing, get_public_profile) is a public page's data.
    const publicFn = /^(get_)?public_|_public$/i.test(f.name) && f.anon_can;
    // A handful of argument sets built from A's identifiers.
    const pick = (type, k) => /uuid/.test(type) ? [...aIds][k % aIds.size]
      : /text|char/.test(type) ? [emailA, [...markers][k % markers.size], 'alice'][k % 3]
      : /int|numeric/.test(type) ? String([1, 1001, 1002][k % 3]) : null;
    const tries = f.args.length ? [0, 1, 2].map(k => f.args.map(t => pick(t, k))) : [[]];
    // Filters left empty (status = null, "all"): what a listing function returns
    // when the caller doesn't narrow it down.
    if (f.args.length) tries.push(f.args.map(() => 'NULL'));
    for (const [actor, can, who] of [[ANON, f.anon_can, 'anon'], [USER_B, f.auth_can, 'cross']]) {
      if (!can) continue;
      for (const [k, args] of tries.entries()) {
        if (args.some(a => a == null)) continue;
        const call = `public.${q(f.name)}(${args.map((a, i) => a === 'NULL' ? `null::${f.args[i]}` : `${esc(a)}::${f.args[i]}`).join(', ')})`;
        const proof = [...markers, IDS.A].filter(m => !args.includes(m));
        if (!proof.length) continue;
        // Keyed on a personal identifier (a phone or email an attacker can guess)?
        // Then "public" doesn't excuse handing back that person's private data.
        const keyedOnPersonal = args.some(a => personalKeys.has(a));
        const r = await check(db, { id: `${f.name}.rpc.${who}.${k}`, table: f.name, cls: 'rpc_leak', kind: 'attack', actor,
          sql: `select count(*) as n from (select x::text as j from ${call} as x) s where s.j ~ $1`, params: [proof.map(reEsc).join('|')], judge: 'count', anyErrorBlocks: true,
          noticeIfLeaked: (publicFn && !keyedOnPersonal) ? `"${f.name}" is named and granted as a public function, so what it returns is meant for everyone; check it only returns what you'd show on a public page` : undefined });
        results.push(r);
        if (r.status === 'leaked') break;
      }
    }
  }

  // Lookups by secret (a share token, an invite code): a wrong secret must
  // return nothing. A parameter named like a column is silently read as the
  // column in SQL functions, and then every call matches.
  const tokenFns = (await db.query(`
    select p.proname as name, format_type(p.prorettype, null) as returns,
      coalesce((select array_agg(format_type(t, null) order by i) from unnest(p.proargtypes) with ordinality a(t, i)), '{}') as args,
      coalesce(p.proargnames, '{}') as argnames,
      has_function_privilege('anon', p.oid, 'EXECUTE') as anon_can
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.prokind = 'f' and p.pronargs between 1 and 3
      and format_type(p.prorettype, null) not in ('trigger', 'event_trigger', 'void', 'boolean')
      and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')`)).rows
    .filter(f => f.argnames.some((n, i) => /token|share|key|code|slug|secret|link/i.test(n) && /text|char|uuid/.test(f.args[i])));
  // With the right secret, a lookup returns the shared item, not its author's
  // email or other account details.
  const shareTokens = [];
  for (const t of schema.filter(x => x.shareTable)) {
    for (const c of t.columns.filter(c => SHARE_TOKEN_COL.test(c) || /^(token|share_token|share_id|public_id|code|slug)$/i.test(c))) {
      const v = (await db.query(`select ${q(c)}::text as v from public.${q(t.name)} where ${q(c)} is not null limit 1`)).rows[0]?.v;
      if (v) shareTokens.push(v);
    }
  }
  for (const t of schema.filter(x => !x.shareTable)) {
    for (const c of t.columns.filter(c => SHARE_TOKEN_COL.test(c))) {
      const v = (await db.query(`select ${q(c)}::text as v from public.${q(t.name)} where ${q(c)} is not null limit 1`)).rows[0]?.v;
      if (v) shareTokens.push(v);
    }
  }
  for (const f of tokenFns.filter(f => f.anon_can)) {
    for (const [k, tok] of shareTokens.slice(0, 3).entries()) {
      const args = f.args.map((t, i) => /token|share|key|code|slug|secret|link/i.test(f.argnames[i] || '') ? `'${tok.replace(/'/g, "''")}'::${t}` : `null::${t}`);
      results.push(await check(db, { id: `${f.name}.rpc.reveals_email.${k}`, table: f.name, cls: 'declared_sensitive', kind: 'attack', actor: ANON,
        sql: `select count(*) as n from (select x::text as j from public.${q(f.name)}(${args.join(', ')}) as x) s where s.j ~* '[a-z0-9._%+-]+@example\\.test'`, judge: 'count', anyErrorBlocks: true }));
    }
  }
  for (const f of tokenFns) {
    const args = f.args.map((t, i) => /token|share|key|code|slug|secret|link/i.test(f.argnames[i] || '') ? (/\[\]$/.test(t) ? `null::${t}` : /uuid/.test(t) ? `'00000000-0000-4000-8000-0000000000ff'::uuid` : `'vc-wrong-secret-0000'::${t}`) : `null::${t}`);
    results.push(await check(db, { id: `${f.name}.rpc.wrong_secret`, table: f.name, cls: 'secret_bypass', kind: 'attack', actor: f.anon_can ? ANON : USER_B,
      // Only stored data coming back counts (a sample user's name, email, id or
      // share token), not an {"error": "invalid token"} reply.
      sql: `select count(*) as n from (select x::text from public.${q(f.name)}(${args.join(', ')}) as x) s where s.x ~* '00000000-0000-4000-8000-|alice|bob|example\\.test|tok-b-'`, judge: 'count', anyErrorBlocks: true }));
  }

  // Functions that change data with their owner's rights (security definer,
  // returning nothing): user B calls each with A's identifiers, and we look at
  // whether any of A's rows changed.
  const keyed = schema.filter(t => t.key && t.keyA != null && !t.skip);
  if (keyed.length) {
    const fp = keyed.map(t => `coalesce((select md5(string_agg(x::text, ',' order by x::text)) from public.${q(t.name)} x where ${q(t.key)}::text = '${String(t.keyA).replace(/'/g, "''")}'), '')`).join(` || '|' || `);
    const writers = (await db.query(`
      select p.proname as name, p.prosrc as src, coalesce((select array_agg(format_type(t, null) order by i) from unnest(p.proargtypes) with ordinality a(t, i)), '{}') as args,
        has_function_privilege('anon', p.oid, 'EXECUTE') as anon_can, has_function_privilege('authenticated', p.oid, 'EXECUTE') as auth_can
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname = 'public' and p.prosecdef and p.prokind = 'f' and p.pronargs between 1 and 4
        and format_type(p.prorettype, null) not in ('trigger', 'event_trigger') and p.prosrc ~* '\\m(update|delete|insert)\\M'
        and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')`)).rows;
    const setup = `create function public.vc_a_state() returns text language sql security definer as $vcs$ select ${fp} $vcs$; grant execute on function public.vc_a_state() to anon, authenticated; create table public.vc_a_snap as select public.vc_a_state() as s; grant select on public.vc_a_snap to anon, authenticated;`;
    for (const f of writers) {
      // A's ids from the tables this function touches come first.
      const touched = Object.keys(idsByTable).filter(n => new RegExp(`\\b${n}\\b`, 'i').test(f.src || ''));
      const idsFor = t => /uuid/.test(t) ? [...touched.flatMap(n => [...idsByTable[n]]), ...aIds] : /int|numeric/.test(t) ? keyed.map(k => String(k.keyA)).filter(v => /^\d+$/.test(v)) : null;
      const firstId = f.args.findIndex(t => idsFor(t)?.length);
      if (firstId < 0) continue;
      const values = [...new Set(idsFor(f.args[firstId]))].slice(0, 4);
      for (const [actor, can, who] of [[USER_B, f.auth_can, 'cross'], [ANON, f.anon_can, 'anon']]) {
        if (!can) continue;
        let hit = null;
        for (const [k, v] of values.entries()) {
          const args = f.args.map((t, i) => i === firstId ? `'${v}'::${t}` : /text|char/.test(t) ? `'cancelled'::${t}` : /bool/.test(t) ? 'true' : /int|numeric/.test(t) ? `0::${t}` : `null::${t}`);
          const r = await check(db, { id: `${f.name}.rpc_write.${who}.${k}`, table: f.name, cls: 'rpc_write', kind: 'attack', actor, setup,
            sql: `with c as materialized (select public.${q(f.name)}(${args.join(', ')})::text as r) select count(*) as n from c, public.vc_a_snap s where public.vc_a_state() <> s.s`, judge: 'count', anyErrorBlocks: true });
          if (r.status === 'leaked') { hit = r; break; }
          if (k === values.length - 1) hit = r;
        }
        if (hit) results.push(hit);
      }
    }
  }

  // The app's own functions still run for their owner: A calls each function
  // A may execute (not triggers) with A's own identifiers. A bug that makes it
  // error (an ambiguous column, a subquery returning several rows) breaks the
  // feature for everyone.
  const callable = (await db.query(`
    select p.proname as name, coalesce((select array_agg(format_type(t, null) order by i) from unnest(p.proargtypes) with ordinality a(t, i)), '{}') as args
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.prokind = 'f' and p.pronargs <= 3 and p.proname !~ '^vc_'
      and format_type(p.prorettype, null) not in ('trigger', 'event_trigger')
      and has_function_privilege('authenticated', p.oid, 'EXECUTE')
      and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')`)).rows;
  for (const f of callable) {
    const own = keyed.map(k => String(k.keyA));
    const arg = t => /\[\]$/.test(t) ? `null::${t}` : /uuid/.test(t) ? `'${IDS.A}'::uuid` : /int|numeric/.test(t) ? `${own.find(v => /^\d+$/.test(v)) || 1}::${t}` : /text|char/.test(t) ? `null::${t}` : /bool/.test(t) ? 'true' : `null::${t}`;
    results.push(await check(db, { id: `${f.name}.legit.call`, table: f.name, cls: 'legit', kind: 'legit', actor: USER_A,
      sql: `select count(*) as n from (select public.${q(f.name)}(${f.args.map(arg).join(', ')})::text) x`, judge: 'count', errorOnly: true, bugOnly: true }));
  }

  // Staff/admin tables get no sample rows (a row would make a test user
  // privileged), so try the attack itself: user B, and an anonymous visitor,
  // insert B into the table.
  // A deployed app already has an admin, so B tries with one in place (the
  // staff user). Some apps let the first user claim admin on a fresh install
  // ("no admin yet"): if B only gets in while the table is empty, that's a
  // notice about the install, not a hole in the running app.
  for (const t of schema.filter(x => x.privilegeProbe && !x.skip)) {
    const seedAdmin = `insert into auth.users (id, email) values ('${IDS.S}', 'sam-staff@example.test') on conflict do nothing; ${t.privilegeProbe.split(IDS.B).join(IDS.S)}`;
    let seedOk = false;
    await db.exec(db.nested ? 'savepoint vc_seed_admin' : 'begin');
    try { await db.exec(seedAdmin); seedOk = true; } catch {}
    await db.exec(db.nested ? 'rollback to savepoint vc_seed_admin; release savepoint vc_seed_admin' : 'rollback');
    const withAdmin = seedOk ? await check(db, { id: `${t.name}.self_grant_admin.join`, table: t.name, cls: 'self_grant_admin', kind: 'attack',
      actor: USER_B, sql: t.privilegeProbe, setup: seedAdmin, judge: 'affected', anyErrorBlocks: true }) : null;
    if (withAdmin) results.push(withAdmin);
    if (!withAdmin || withAdmin.status === 'blocked') results.push(await check(db, { id: `${t.name}.self_grant_admin.${withAdmin ? 'first_user' : 'join'}`, table: t.name, cls: 'self_grant_admin', kind: 'attack',
      actor: USER_B, sql: t.privilegeProbe, judge: 'affected', anyErrorBlocks: true,
      noticeIfLeaked: withAdmin ? `on a fresh install with no admin yet, the first user to reach "${t.name}" becomes admin; claim it right after deploying (or create the first admin from the server)` : undefined }));
    results.push(await check(db, { id: `${t.name}.anon.self_grant_admin`, table: t.name, cls: 'self_grant_admin', kind: 'attack',
      actor: ANON, sql: t.privilegeProbe, judge: 'affected', anyErrorBlocks: true }));
  }

  // Whoever creates a team becomes a member of it: through a trigger, or by
  // adding themselves. With neither, a new team is invisible to its creator
  // and nobody can ever invite anyone into it.
  for (const m of schema.filter(x => x.membership && x.owner && x.tenant && !x.skip)) {
    const fk = (m.fks || []).find(f => f.col === m.tenant && f.refSchema === 'public');
    const G = fk && schema.find(x => x.name === fk.refTable);
    if (!G || !(G.policies || []).some(p => p.cmd === 'INSERT' || p.cmd === 'ALL')) continue;
    const mRow = (await db.query(`select to_jsonb(x) as r from public.${q(m.name)} x where ${q(m.owner)}::text = $1 limit 1`, [IDS.B])).rows[0]?.r;
    if (!mRow) continue;
    const gRow = (await db.query(`select to_jsonb(g) as r from public.${q(G.name)} g where ${q(fk.refCol)}::text = $1`, [String(mRow[m.tenant])])).rows[0]?.r;
    if (!gRow) continue;
    if (G.owner) gRow[G.owner] = IDS.B;
    // The app creates the team without reading it back (the creator can't see
    // it until they're a member), so pick the new id up front when it's a uuid.
    const uuidPk = typeof gRow[fk.refCol] === 'string' && /^[0-9a-f-]{36}$/i.test(gRow[fk.refCol]);
    const gIns = insertSql({ ...G, generated: G.generated.filter(c => !(uuidPk && c === fk.refCol)) }, uuidPk ? { ...gRow, [fk.refCol]: '__GID__' } : gRow);
    const gJson = `('${gIns.params[0].replace(/'/g, "''")}')::jsonb`.replace('"__GID__"', `"' || gid || '"`);
    const gSql = uuidPk
      ? `gid := gen_random_uuid()::text; ${gIns.sql.replace('$1::jsonb', gJson)}`
      : `${gIns.sql.replace('$1::jsonb', gJson)} returning ${q(fk.refCol)}::text into gid`;
    const row = { ...mRow, [m.owner]: IDS.B };
    if (m.memberRole) row[m.memberRole.col] = m.memberRole.admin;
    delete row[m.tenant];
    const cols = Object.keys(row).filter(c => !m.generated.includes(c)).concat([m.tenant]);
    const mSql = `insert into public.${q(m.name)} (${cols.map(q).join(', ')}) select ${cols.map(q).join(', ')} from jsonb_populate_record(null::public.${q(m.name)}, '${JSON.stringify(Object.fromEntries(Object.entries(row).filter(([c]) => !m.generated.includes(c)))).replace(/'/g, "''")}'::jsonb || jsonb_build_object('${m.tenant}', gid))`;
    const setup = [
      `create function public.vc_is_member_b(gid text) returns boolean language sql security definer as $f$ select exists (select 1 from public.${q(m.name)} where ${q(m.owner)}::text = '${IDS.B}' and ${q(m.tenant)}::text = gid) $f$;`,
      `create function public.vc_new_group() returns bigint language plpgsql security invoker as $f$ declare gid text; begin ${gSql}; if public.vc_is_member_b(gid) then return 1; end if; ${mSql}; return 1; end $f$;`,
      `grant execute on function public.vc_is_member_b(text), public.vc_new_group() to authenticated;`].join(' ');
    results.push(await check(db, { id: `${m.name}.legit.creator_joins`, table: m.name, cls: 'legit', kind: 'legit', setup,
      actor: USER_B, sql: `select public.vc_new_group() as n`, judge: 'count' }));
    // The app creates a team and reads it back in one call (insert().select()):
    // the creator must be able to see the row they just made.
    if (G.owner) {
      const g2 = insertSql(G, gRow);
      results.push(await check(db, { id: `${G.name}.legit.create_and_read_back`, table: G.name, cls: 'legit', kind: 'legit', actor: USER_B,
        sql: `with i as (${g2.sql} returning 1) select count(*) as n from i`, params: g2.params, judge: 'count' }));
    }
  }

  // Signing up still works: whatever the app runs when a user is created
  // (a profile trigger, accepting pending invitations) must not error.
  if ((await db.query(`select count(*)::int as n from pg_trigger tg join pg_class c on c.oid = tg.tgrelid join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'auth' and c.relname = 'users' and not tg.tgisinternal`)).rows[0].n) {
    results.push(await check(db, { id: 'auth.legit.signup', table: 'auth.users', cls: 'legit', kind: 'legit', actor: USER_C,
      setup: `insert into auth.users (id, email) values ('${IDS.C}', 'carol@example.test') on conflict do nothing`,
      sql: `select 1 as n`, judge: 'count' }));
  }

  // Staff still do their job: a staff member (added to the staff table the
  // way the server would) can read the rows the staff policies are for. Without
  // this, a fix that simply drops the staff policies would look perfect.
  const fnSrc = (await db.query(`select p.proname as name, p.prosrc as src from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public'`)).rows;
  // Staff come from a staff table (a row makes you staff) or from a role
  // column (profiles.role = 'admin'); either way, made the way the server would.
  const staffSources = schema.filter(x => x.privilegeProbe && !x.skip).map(P => ({ P, setup: P.privilegeProbe.split(IDS.B).join(IDS.S) }));
  if (!staffSources.length) {
    for (const R of schema.filter(x => x.role && x.owner && !x.skip && !x.membership)) {
      const rRow = (await db.query(`select to_jsonb(x) as r from public.${q(R.name)} x where ${q(R.owner)}::text = $1 limit 1`, [IDS.B])).rows[0]?.r;
      if (!rRow) continue;
      // One staff user per privileged role value the app names (staff, admin,
      // moderator...), so each policy is tried with the role it asks for.
      const col = R.columnsInfo?.find(c => c.name === R.role.col);
      const values = [...new Set([...(R.role.values || []).filter(v => /admin|staff|manager|moderator|owner|super|editor|support/i.test(v)), R.role.admin])];
      for (const v of values) {
        const row = { ...rRow, [R.owner]: IDS.S, [R.role.col]: v };
        const ins = insertSql(R, row);
        const inline = ins.sql.replace('$1::jsonb', `'${ins.params[0].replace(/'/g, "''")}'::jsonb`);
        staffSources.push({ P: R, value: v, setup: `${inline} on conflict do nothing; update public.${q(R.name)} set ${q(R.role.col)} = '${String(v).replace(/'/g, "''")}' where ${q(R.owner)}::text = '${IDS.S}'` });
      }
    }
  }
  for (const { P, setup: makeStaff, value } of staffSources) {
    const mentions = new RegExp(`\\b${P.name}\\b`, 'i');
    // With a role value, only helpers and policies that name that value count.
    const named = src => !value || new RegExp(`'${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'`, 'i').test(src);
    const helpers = fnSrc.filter(f => mentions.test(f.src || '') && named(f.src || '')).map(f => f.name);
    const refers = text => (mentions.test(text) && named(text)) || helpers.some(h => new RegExp(`\\b${h}\\s*\\(`, 'i').test(text));
    const setup = `insert into auth.users (id, email) values ('${IDS.S}', 'sam-staff@example.test') on conflict do nothing; ${makeStaff};`;
    for (const t of schema.filter(x => x.key && !x.skip && x.name !== P.name && x.keyA != null)) {
      const staffRead = (t.policies || []).some(p => ['SELECT', 'ALL'].includes(p.cmd) && refers(p.text));
      if (!staffRead) continue;
      const read = await check(db, { id: `${t.name}.legit.staff_read${value ? `.${value}` : ''}`, table: t.name, cls: 'legit', kind: 'legit', setup,
        actor: STAFF, sql: `select count(*) as n from public.${q(t.name)} where ${q(t.key)}::text = '${String(t.keyA).replace(/'/g, "''")}'`, judge: 'count', soft: true });
      results.push(read);
      // Staff change the fields customers can't (an order's status). When staff
      // can see the row, being unable to update it breaks the staff feature.
      const canSee = read.status === 'ok' && read.proof?.observed?.rows_visible > 0;
      for (const { col, value: newVal } of (t.tamper || []).filter(x => x.kind === 'status').slice(0, 1)) {
        results.push(await check(db, { id: `${t.name}.legit.staff_update.${col}${value ? `.${value}` : ''}`, table: t.name, cls: 'legit', kind: 'legit', setup,
          actor: STAFF, sql: `with u as (update public.${q(t.name)} set ${q(col)} = $1 where ${q(t.key)}::text = '${String(t.keyA).replace(/'/g, "''")}' returning 1) select count(*) as n from u`, params: [newVal], judge: 'count', soft: !canSee }));
      }
    }
  }

  // Views: a view runs with its owner's rights and skips row level security
  // unless it is created with security_invoker. Attack through every view whose
  // underlying tables are private: can a visitor or user B see rows through the
  // view that the tables themselves would hide?
  const byTable = new Map(results.map(r => [r.id, r.status]));
  const privateFor = (base, who) => {
    if (base.schema !== 'public') return true; // auth.users and friends
    const t = schema.find(s => s.name === base.table);
    if (!t || t.publicRead) return false;
    return who === 'anon' ? byTable.get(`${t.name}.anon.read`) === 'blocked' : byTable.get(`${t.name}.cross.read`) === 'blocked';
  };
  const views = (await db.query(`
    select distinct v.relname as view, v.relkind as kind, tn.nspname as schema, t.relname as table,
      coalesce(array_to_string(v.reloptions, ','), '') as options
    from pg_class v join pg_namespace vn on vn.oid = v.relnamespace
    join pg_rewrite r on r.ev_class = v.oid
    join pg_depend d on d.objid = r.oid and d.classid = 'pg_rewrite'::regclass and d.refclassid = 'pg_class'::regclass
    join pg_class t on t.oid = d.refobjid and t.relkind in ('r', 'p') join pg_namespace tn on tn.oid = t.relnamespace
    where vn.nspname = 'public' and v.relkind in ('v', 'm') and t.oid <> v.oid`)).rows;
  for (const name of [...new Set(views.map(v => v.view))]) {
    const bases = views.filter(v => v.view === name);
    const V = `public.${q(name)}`;
    const total = Number((await db.query(`select count(*)::int as n from ${V}`)).rows[0].n);
    if (!total) continue;
    const baseList = bases.map(b => `${b.schema}.${b.table}`).join(', ');
    // A view that publishes content on purpose (shared or published rows) is
    // fine; what matters is private rows or personal data coming through it.
    // With an owner column, target A's (private) rows; with emails or tokens in
    // the view, any visible row counts.
    const vcols = (await db.query(`select column_name as c, data_type as t from information_schema.columns where table_schema = 'public' and table_name = $1`, [name])).rows;
    const ownerCol = vcols.find(c => c.t === 'uuid' && /^(user_id|owner_id|author_id|created_by|customer_id|profile_id|creator_id|owner)$/.test(c.c))?.c;
    const exposes = vcols.some(c => SENSITIVE_COL.test(c.c) || SECRET_COL.test(c.c));
    const aOnly = ownerCol && !exposes ? ` where ${q(ownerCol)} = '${IDS.A}'` : '';
    // The precise test: does the view show more rows than the same query would
    // if it ran with the caller's rights? Build that invoker copy in the attack's
    // savepoint and compare. (Views over auth.* or materialized views can't be
    // compared this way; there, any private row coming through counts.)
    const comparable = bases[0].kind === 'v' && bases.every(b => b.schema === 'public');
    const def = comparable ? (await db.query(`select pg_get_viewdef($1::regclass) as d`, [V])).rows[0].d : null;
    const copy = `vc_invoker_${name}`.slice(0, 60);
    // The invoker side goes through a function that counts 0 when the caller's
    // own query would error (a policy loop, a table they can't read): then
    // every row the view shows is a row they couldn't otherwise get.
    const fn = `vc_invoker_count_${name}`.slice(0, 60);
    const setup = comparable ? [
      `create view public.${q(copy)} with (security_invoker = true) as ${def.replace(/;\s*$/, '')};`,
      `grant select on public.${q(copy)} to anon, authenticated;`,
      `create function public.${q(fn)}(w text) returns bigint language plpgsql security invoker as $vcf$ declare n bigint; begin execute 'select count(*) from public.${q(copy).replace(/'/g, "''")}' || w into n; return n; exception when others then return 0; end $vcf$;`,
      `grant execute on function public.${q(fn)}(text) to anon, authenticated;`].join(' ') : null;
    const excess = (where = '') => `select greatest(0, (select count(*) from ${V}${where}) - public.${q(fn)}(${"'" + where.replace(/'/g, "''") + "'"})) as n`;
    // A view the builder declared public is judged like a public table: only
    // personal data or secrets coming through it count.
    // Rows the app shares on purpose (a share token set, marked public or
    // published) should stay visible through the view: a fix that makes the
    // view respect row security mustn't break the share links it serves.
    const sharedCond = vcols.filter(c => SHARE_TOKEN_COL.test(c.c)).map(c => `${q(c.c)} is not null`)
      .concat(vcols.filter(c => c.t === 'boolean' && /^(is_)?(public|published|shared|visible)$/i.test(c.c)).map(c => `${q(c.c)}`));
    if (sharedCond.length) {
      // A view with a share-token column exists to serve share links, so an
      // anonymous visitor must see shared rows through it.
      const tokenView = vcols.some(c => SHARE_TOKEN_COL.test(c.c));
      const anySharedRow = Number((await db.query(`select count(*)::int as n from ${V} where ${sharedCond.join(' or ')}`)).rows[0].n) > 0;
      if (anySharedRow) results.push(await check(db, { id: `${name}.legit.view_shared`, table: name, cls: 'legit', kind: 'legit', actor: ANON,
        sql: `select count(*) as n from ${V} where ${sharedCond.join(' or ')}`, judge: 'count', soft: !tokenView }));
    }
    const declaredOpen = (schema.manifest?.publicTables || []).some(p => new RegExp(p, 'i').test(name));
    if (declaredOpen && !exposes) continue;
    // A view that carries no personal data or secrets and no per-user id column
    // (an availability calendar, an aggregate count) exposes nothing about a
    // particular user even if it reads private tables: a notice, not a leak.
    // An availability/schedule view (room types, dates, open slots) exposes
    // nothing about a particular user. But a view carrying per-entity ids or
    // metrics (a learner's score totals, an account balance) still leaks that
    // entity's data across users, so those stay leaks.
    const perEntity = vcols.some(c => /_id$|(^|_)(total|totals|sum|amount|count|score|scores|balance|revenue|points|rating|salary|grade|marks?)(_|s|$)/i.test(c.c));
    const viewNotice = !exposes && !ownerCol && !perEntity
      ? `the "${name}" view reads private tables with its owner's rights, but exposes no personal, per-user or per-entity columns (an aggregate or availability view). Confirm it only shows what everyone may see.`
      : undefined;
    if (bases.some(b => privateFor(b, 'anon'))) {
      results.push(await check(db, { id: `${name}.view.anon.read`, table: name, cls: 'view_bypass', kind: 'attack',
        actor: ANON, sql: comparable ? excess(aOnly) : `select count(*) as n from ${V}${aOnly}`, setup, judge: 'count', note: baseList, noticeIfLeaked: viewNotice }));
    }
    if (total >= 2 && bases.some(b => privateFor(b, 'cross'))) {
      // B sees rows through the view that the tables themselves would hide.
      results.push(await check(db, { id: `${name}.view.cross.read`, table: name, cls: 'view_bypass', kind: 'attack',
        actor: USER_B, sql: comparable ? excess() : `select count(*) as n from ${V}`, setup, judge: 'count', allowed: comparable ? 0 : total - 1, noticeIfLeaked: viewNotice }));
    }
  }

  // Public buckets: a file in a public bucket is served to anyone with its URL,
  // whatever the storage policies say. Fine for avatars and product photos; a
  // leak for buckets whose name says they hold documents.
  const buckets = (await db.query(`select id, public from storage.buckets`)).rows;
  // Whole words only: "profile_images" isn't about files.
  const privateBucket = id => /id_?cards?/i.test(id) || String(id).split(/[^a-z0-9]+/i).some(w => /^(docs?|documents?|invoices?|receipts?|private|secure|contracts?|passports?|medical|reports?|backups?|exports?|attachments?|uploads?|files?|user_?files)$/i.test(w));
  for (const b of buckets.filter(b => b.public || privateBucket(b.id))) {
    const privateLooking = privateBucket(b.id);
    results.push(await check(db, { id: `storage.bucket.${b.id}.public`, table: `storage.buckets/${b.id}`, cls: 'public_bucket', kind: 'attack', actor: ANON,
      sql: `select count(*) as n from storage.buckets where id = '${String(b.id).replace(/'/g, "''")}' and public`, judge: 'count',
      noticeIfLeaked: privateLooking ? undefined : `bucket "${b.id}" is public, so anyone with a file's URL can download it; fine for images meant to be shown, not for private files` }));
  }

  // Uploads, for every bucket, whether or not any file exists yet: an anonymous
  // visitor putting a file in, and user B writing into user A's folder (apps
  // commonly key folders by user id: <uid>/avatar.png).
  // Folder-based rules (storage.foldername(name)[1] = auth.uid()) are the ones
  // a path can get around; owner-based rules use the uploader Supabase records.
  const folderRules = (await db.query(`select coalesce(string_agg(coalesce(qual, '') || ' ' || coalesce(with_check, ''), ' '), '') as t from pg_policies where schemaname = 'storage' and tablename = 'objects' and cmd in ('INSERT', 'ALL')`)).rows[0].t;
  const folderBased = /foldername|split_part\s*\(\s*name|name\s+like|starts_with\s*\(\s*name|path_tokens/i.test(folderRules)
    && !/owner(_id)?\s*=\s*\(?\s*(select\s+)?auth\.uid\(\)|auth\.uid\(\)\s*\)?\s*=\s*owner/i.test(folderRules);
  // Anyone uploading into a bucket of images meant to be shown (avatars) is a
  // warning worth fixing before launch; into any other bucket, a hole.
  const mediaBucket = id => /avatar|image|img|photo|picture|logo|media|public|thumbnail|banner|icon/i.test(id);
  // SELECT policies anonymous visitors can use to read a bucket. When the same
  // bucket anyone can upload to is also plainly anon-readable, an uploaded file
  // is served publicly from your domain (phishing pages, malware under your
  // brand), so an open upload there is a real hole, not just storage fill.
  const readPolicies = (await db.query(`select coalesce(qual, '') as q, coalesce(array_to_string(roles, ','), '') as roles from pg_policies where schemaname = 'storage' and tablename = 'objects' and cmd in ('SELECT', 'ALL')`)).rows;
  const anonServe = id => {
    const esc = String(id).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return readPolicies.some(p => {
      const anonRole = !p.roles.trim() || /(^|,)(anon|public)(,|$)/i.test(p.roles);
      if (!anonRole) return false;
      // A read gated by who is signed in is not a public serve path.
      if (/auth\.uid\(\)|auth\.jwt|auth\.role\(\)|allow_any_operation|['"]authenticated['"]|is_authenticated/i.test(p.q)) return false;
      return new RegExp(`bucket_id\\s*=\\s*'${esc}'`, 'i').test(p.q) || /^\s*\(?\s*true\s*\)?\s*$/i.test(p.q) || !p.q.trim();
    });
  };
  for (const b of buckets) {
    const bid = String(b.id).replace(/'/g, "''");
    results.push(await check(db, { id: `storage.anon.upload.${b.id}`, table: `storage.objects/${b.id}`, cls: 'storage_upload', kind: 'attack', actor: ANON,
      sql: `insert into storage.objects (bucket_id, name) values ('${bid}', 'vc-probe/anon-upload.txt')`, judge: 'affected', anyErrorBlocks: true,
      // Anyone uploading into a bucket of images meant to be shown (avatars,
      // Supabase's own quickstart) is worth flagging but not a data leak; into a
      // documents/private bucket it is a real hole.
      noticeIfLeaked: (mediaBucket(b.id) && !anonServe(b.id)) ? `anyone, without signing in, can upload files to the "${b.id}" bucket (this is Supabase's quickstart avatar policy). Fine for public images, but it lets anyone fill your storage or host files under your domain — limit uploads to signed-in users and their own folder before launch.` : undefined }));
    // Only meaningful where users upload into their own folder at all.
    const own = folderBased ? await runAs(db, USER_A, `insert into storage.objects (bucket_id, name, owner, owner_id) values ('${bid}', '${IDS.A}/vc-own.txt', '${IDS.A}', '${IDS.A}')`) : null;
    if (own?.ok && own.affected > 0) results.push(await check(db, { id: `storage.cross.upload_into_other_folder.${b.id}`, table: `storage.objects/${b.id}`, cls: 'storage_upload', kind: 'attack', actor: USER_B,
      sql: `insert into storage.objects (bucket_id, name, owner, owner_id) values ('${bid}', '${IDS.A}/vc-probe.txt', '${IDS.B}', '${IDS.B}')`, judge: 'affected', anyErrorBlocks: true }));
  }

  // Storage: files are a separate policy system from tables.
  const objs = await db.query(`select count(*)::int as n from storage.objects where owner = $1`, [IDS.A]);
  if (objs.rows[0].n > 0) {
    const where = `owner = '${IDS.A}'`;
    results.push(await check(db, { id: 'storage.anon.read', table: 'storage.objects', cls: 'storage_read', kind: 'attack',
      actor: ANON, sql: `select count(*) as n from storage.objects where ${where}`, judge: 'count' }));
    results.push(await check(db, { id: 'storage.cross.read', table: 'storage.objects', cls: 'storage_read', kind: 'attack',
      actor: USER_B, sql: `select count(*) as n from storage.objects where ${where}`, judge: 'count' }));
    results.push(await check(db, { id: 'storage.cross.delete', table: 'storage.objects', cls: 'storage_write', kind: 'attack',
      actor: USER_B, sql: `delete from storage.objects where ${where}`, judge: 'affected' }));
    const ownB = (await db.query(`select count(*)::int as n from storage.objects where owner = $1`, [IDS.B])).rows[0].n;
    results.push(await check(db, { id: 'storage.cross.blind_delete', table: 'storage.objects', cls: 'storage_write', kind: 'attack',
      actor: USER_B, sql: `delete from storage.objects`, judge: 'affected', allowed: ownB }));
    results.push(await check(db, { id: 'storage.legit.read_own', table: 'storage.objects', cls: 'legit', kind: 'legit',
      actor: USER_A, sql: `select count(*) as n from storage.objects where ${where}`, judge: 'count' }));
  }

  // Collaborator ownership takeover: an app that lets a shared collaborator
  // (an "editor" invited through a shares/members table) edit an item, but whose
  // UPDATE policy doesn't protect the owner column, lets that collaborator
  // reassign the item to themselves — stealing it from the real owner. Seed B as
  // a collaborator on A's row, then have B set the owner column to B.
  for (const t of schema) {
    if (only && !only.has(t.name)) continue;
    if (!t.owner || t.membership || t.publicRead || !t.key || t.keyKind !== 'owner') continue;
    // The update rule must extend write past the plain owner (a share/member
    // table or an access-helper function), else there's no collaborator path.
    const updPol = (t.policies || []).filter(p => /UPDATE|ALL/i.test(p.cmd || 'ALL')).map(p => p.text).join(' ');
    const ownerOnlyUpdate = updPol && /^[\s()]*$/.test(updPol.replace(new RegExp(`\\(?(\\w+\\.)?"?${t.owner}"?\\)?(::\\w+)?\\s*=\\s*\\(?\\s*(select\\s+)?auth\\.uid\\(\\)\\s*\\)?|auth\\.uid\\(\\)\\s*\\)?\\s*=\\s*\\(?(\\w+\\.)?"?${t.owner}"?`, 'gi'), ' ').replace(/\b(and|or|true)\b/gi, ' ').trim());
    if (!updPol || ownerOnlyUpdate) continue;
    // Taking the owner column only escalates if ownership grants a right the
    // collaborator lacks. Require the owner column to gate DELETE (owner-only
    // deletion) — the classic right a shared editor shouldn't have. A
    // "created_by" that only adds an OR-branch to read is cosmetic (a member
    // already reads), so those don't count.
    const ownerGatesDelete = (t.policies || []).some(p => /DELETE|ALL/i.test(p.cmd || 'ALL')
      && new RegExp(`\\(?(\\w+\\.)?"?${t.owner}"?\\)?(::\\w+)?\\s*=\\s*\\(?\\s*(select\\s+)?auth\\.uid\\(\\)|auth\\.uid\\(\\)\\s*\\)?\\s*=\\s*\\(?(\\w+\\.)?"?${t.owner}"?`, 'i').test(p.text || ''));
    if (!ownerGatesDelete) continue;
    // A grant table: rows tying a user to one of A's items in this table. It
    // must look like a sharing/membership table (its name, a role column, or a
    // FK to both the item and a user) — not just any child table.
    const looksLikeGrant = g => /(share|member|collaborator|access|invit|grant|permission|guardian|caregiver|team)/i.test(g.name)
      || (g.columns || []).some(c => /^(role|permission|access|access_level|share_role)$/i.test(c));
    const grant = schema.filter(g => g.name !== t.name && (g.fks || []).some(f => f.refSchema === 'public' && f.refTable === t.name)
      && (g.fks || []).some(f => (f.refSchema === 'auth' && f.refTable === 'users') || /^(user_id|member_id|shared_with|collaborator_id|invitee_id|profile_id)$/i.test(f.col)))
      .sort((a, b) => (looksLikeGrant(b) ? 1 : 0) - (looksLikeGrant(a) ? 1 : 0))[0];
    if (!grant || !looksLikeGrant(grant)) continue;
    const petFk = grant.fks.find(f => f.refSchema === 'public' && f.refTable === t.name);
    const userFk = grant.fks.find(f => /^(user_id|member_id|shared_with|collaborator_id|invitee_id|profile_id)$/i.test(f.col)) || grant.fks.find(f => f.refSchema === 'auth' && f.refTable === 'users');
    if (!petFk || !userFk) continue;
    // A's item id.
    const aItem = (await db.query(`select ${q(petFk.refCol)}::text as v from public.${q(t.name)} where ${q(t.owner)}::text = $1 limit 1`, [IDS.A]).catch(() => ({ rows: [] }))).rows[0]?.v;
    if (aItem == null) continue;
    // Grant B collaborator access to A's item, filling the grant row's required
    // columns (a role column gets its highest value). Done as the setup, then B
    // attempts to take ownership.
    const roleCol = grant.columns.find(c => /^(role|permission|access|access_level|share_role)$/i.test(c));
    const roleVal = roleCol ? await (async () => { const r = await db.query(`select pg_get_constraintdef(oid) as d from pg_constraint where conrelid = $1::regclass and contype = 'c'`, [`public.${q(grant.name)}`]).catch(() => ({ rows: [] })); const vals = [...String(r.rows.map(x=>x.d).join(' ')).matchAll(/'([^']+)'/g)].map(m => m[1]); return vals.find(v => /edit|write|admin|manage|owner|full/i.test(v)) || vals[0] || 'editor'; })() : null;
    const cols = [petFk.col, userFk.col, ...(roleCol ? [roleCol] : [])];
    const vals = [`'${aItem}'`, `'${IDS.B}'`, ...(roleCol ? [`'${String(roleVal).replace(/'/g, "''")}'`] : [])];
    const setup = `insert into public.${q(grant.name)} (${cols.map(q).join(', ')}) values (${vals.join(', ')}) on conflict do nothing`;
    // Does the seed even work (is this the right grant shape)? If not, skip quietly.
    if (!await quietly(db, setup)) continue;
    results.push(await check(db, { id: `${t.name}.collab.take_ownership`, table: t.name, cls: 'privilege_escalation', kind: 'attack',
      actor: USER_B, setup, sql: `update public.${q(t.name)} set ${q(t.owner)} = '${IDS.B}' where ${q(petFk.refCol)}::text = '${aItem}'`,
      judge: 'affected', anyErrorBlocks: true,
      note: `B, invited only as a collaborator on this ${t.name}, reassigned it to themselves — the update rule checks collaborator access but not that "${t.owner}" stays the real owner` }));
  }

  return applyDependencies(results);
}

// skipped: tables left empty on purpose (share links, invitations, staff).
// Any other table that couldn't be tested means "safe" can't be claimed:
// the verdict is "incomplete", or "untested" when no attack ran at all.
export function summarize(results, { skipped = [] } = {}) {
  const attacks = results.filter(r => r.kind === 'attack' && r.status !== 'inconclusive' && r.status !== 'notice');
  const leaked = attacks.filter(r => r.status === 'leaked');
  const legit = results.filter(r => r.kind === 'legit');
  const broken = legit.filter(r => r.status === 'broken');
  const inconclusive = results.filter(r => r.status === 'inconclusive');
  const notTested = results.filter(r => r.kind === 'coverage').map(r => r.table);
  const raw = attacks.length ? Math.floor(100 * (attacks.length - leaked.length) / attacks.length) : 0;
  // One real leak is a failing grade no matter how many other attacks were blocked;
  // an app that blocks its own users can't score as fully safe either.
  const guardScore = leaked.length ? Math.min(raw, 59) : broken.length ? Math.min(raw, 79) : raw;
  const missed = notTested.filter(t => !skipped.includes(t));
  // An app that can't run for its own users (a policy that loops on the
  // identity table everything reads, or most of its tables locked to their own
  // owners) is broken first. Read-side findings on such an app are often side
  // effects of the same misconfiguration, so when the only leaks are read-side
  // or bookkeeping ones, "breaks the app" is the primary verdict and the leaks
  // stay listed for review. Any write, impersonation or escalation leak still
  // makes it unsafe.
  const STRONG = /^(anon_write|cross_user_write|impersonated_insert|self_grant_admin|team_self_promotion|tenant_self_join|privilege_escalation|storage_(read|write|upload)|service_key_exposed|declared_sensitive|public_secret|trusts_user_metadata|secret_bypass|definer_exposed|rpc_write|shared_data_write|token_enumeration)$/;
  const brokenTables = new Set(broken.map(r => r.table));
  const legitTables = new Set(legit.map(r => r.table));
  const recursionOnCore = broken.some(r => /infinite recursion/i.test(r.proof?.observed?.error || '') && /^(profiles?|users?|accounts?|members?|user_profiles|memberships?)$/i.test(r.table));
  const mostlyBroken = legitTables.size >= 3 && brokenTables.size / legitTables.size >= 0.5;
  const leakTables = new Set(leaked.map(r => r.table));
  const brokenFirst = leaked.length && broken.length && (recursionOnCore || mostlyBroken)
    && leaked.every(r => !STRONG.test(r.class)) && leakTables.size <= 4;
  const verdict = brokenFirst ? 'breaks_app' : leaked.length ? 'unsafe' : broken.length ? 'breaks_app'
    : !attacks.length ? 'untested' : missed.length ? 'incomplete' : 'safe';
  return {
    verdict,
    guardScore: verdict === 'untested' ? null : verdict === 'incomplete' ? Math.min(guardScore, 79) : guardScore,
    attacks: { run: attacks.length, blocked: attacks.length - leaked.length, leaked: leaked.length },
    legit: { run: legit.length, ok: legit.length - broken.length, broken: broken.length },
    inconclusive: inconclusive.length,
    notTested,
    missed,
    ...(brokenFirst ? { alsoReview: leaked.map(r => r.id) } : {}),
    notices: results.filter(r => r.status === 'notice').map(r => ({ id: r.id, table: r.table, note: r.proof.note })),
  };
}
