// Reads the schema and works out, for each public table, whose row is whose:
//  - owner:  a column pointing at the user (foreign key to auth.users, or a common name)
//  - tenant: a column pointing at a group the user belongs to through a membership table
//            (or a common name like org_id)
//  - parent: otherwise, a foreign key to a table that has one of the above
//            (tasks -> projects -> teams)
// It also finds user-level role columns (profiles.role, user_roles.role, is_admin)
// that policies or functions rely on, so the gauntlet can try to self-grant admin.
// Inference is conservative; a manifest can override it.
import { IDS, EMAILS } from './db.js';
import { loadCatalog, authText, userFkCols, findMemberships, ROLE_COL, ADMIN_BOOL_COL, roleValues, highestRole, identityTables, userMatch } from './catalog.js';

const OWNER_NAMES = ['user_id', 'owner_id', 'author_id', 'created_by', 'profile_id', 'owner', 'creator_id'];
const TENANT_NAMES = ['org_id', 'organization_id', 'tenant_id', 'team_id', 'workspace_id', 'account_id', 'company_id'];
const ROLE_TABLE = /role|admin|permission/i;
const q = n => `"${n.replace(/"/g, '""')}"`;

// The value an owner would set to cheat, for money and status columns.
const PAID_BOOL = /^(is_)?(paid|verified|approved|featured|refunded|premium|pro|vip|fulfilled|shipped|delivered)$/i;
const MONEY = /(^|_)(price|amount|total|subtotal|cost|fee|discount|tax)(_cents|_amount)?$/i;
const BALANCE = /(^|_)(credits?|balance|points|tokens_left|quota|wallet)(_cents)?$/i;
const STATUS = /^(status|state|payment_status|order_status|fulfillment_status|plan|tier|subscription_(status|tier|plan))$/i;
const PRIVILEGED_STATUS = /^(paid|succeeded|completed|complete|delivered|shipped|fulfilled|approved|refunded|active|pro|premium|enterprise|vip)$/i;
// The free / entry tier of a plan or tier enum: any other value is an upgrade.
const BASE_TIER = /^(free|basic|none|starter|trial|standard|default|guest|regular|member|inactive|pending|new|lite|hobby)$/i;
// Counters of what other people did (likes, views, votes, downloads): a
// user's own tally of their own activity (glasses_count, note_count,
// success_count) isn't one.
const TRUST_FIELD = /(^|_)(paid|payment_status|verified|approved|credits?|balance|plan|tier|subscription(_\w+)?|premium|pro|vip|featured|refunded|wallet|quota|tokens_left)$/i;
const COUNTER = /(^|_)(likes?|votes?|upvotes?|downvotes?|views?|helpful|followers?|reviews?|ratings?|downloads?|sales|shares|clicks|impressions|redemptions?|uses|usage|purchases?)(_count|_total)?$|^(helpful|view|like|vote|follower|review|rating|download|share|click|usage|use|redemption|purchase)_count$/i;
// Fields some other party acts on even when only the owner can see the row:
// payment, verification, approval, credits and plan.
function tamperValue(c) {
  if (c.category === 'B' && PAID_BOOL.test(c.name)) return 'true';
  if (c.category === 'N' && MONEY.test(c.name)) return '0';
  if (c.category === 'N' && BALANCE.test(c.name)) return '999999';
  if ((c.category === 'S' || c.enum) && STATUS.test(c.name)) {
    if (c.values?.length) {
      const def = String(c.defaultExpr || '').replace(/::[\w ]+$/, '').replace(/^'|'$/g, '').trim();
      return c.values.find(v => /^paid$/i.test(v))
        || c.values.find(v => PRIVILEGED_STATUS.test(v))
        // A plan/tier upgrade: any value that isn't the free/entry tier or the
        // current default (plan 'free' -> 'lifetime', tier 'basic' -> 'gold').
        || (/(^|_)(plan|tier|subscription)/i.test(c.name) ? c.values.find(v => !BASE_TIER.test(v) && v !== def) : null)
        || null;
    }
    return 'paid';
  }
  return null;
}
const isUuidCol = (t, n) => t.columns.some(c => c.name === n && c.category === 'U');
const matches = (patterns, name) => (patterns || []).some(p => new RegExp(p, 'i').test(name));

export async function introspect(db, manifest = {}) {
  const catalog = await loadCatalog(db);
  const overrides = manifest.tables || {};
  // A manifest can name the membership table; its user and group columns are
  // still read from the schema, so the group table itself gets checked too.
  let memberships = findMemberships(catalog);
  if (manifest.membership !== undefined) {
    memberships = memberships.filter(m => m.table === manifest.membership);
    const mt = catalog.find(t => t.name === manifest.membership);
    if (!memberships.length && mt) {
      const user = userFkCols(mt)[0] || OWNER_NAMES.find(n => isUuidCol(mt, n));
      const group = mt.fks.find(f => f.refSchema === 'public' && f.refTable !== mt.name);
      if (user && group) memberships = [{ table: mt.name, userCol: user, groupCol: group.col, group: group.refTable, groupPk: group.refCol }];
    }
  }
  // A per-user account (accounts.user_id unique, other tables keyed by
  // account_id): a group of one, whose "membership" is the account row itself.
  const accountGroups = catalog.filter(p => p.pk.length === 1 && !memberships.some(m => m.table === p.name || m.group === p.name)).map(p => {
    const u = userFkCols(p).find(c => c !== p.pk[0] && (p.uniques || []).some(x => x.length === 1 && x[0] === c));
    return u && catalog.some(x => x.name !== p.name && x.fks.some(f => f.refSchema === 'public' && f.refTable === p.name && f.refCol === p.pk[0]))
      ? { table: p.name, userCol: u, groupCol: p.pk[0], group: p.name, groupPk: p.pk[0], account: true } : null;
  }).filter(Boolean);
  // The app's own users table (users."authId" = auth.uid()): a group of one
  // too; tables pointing at users.id belong to that user.
  for (const it of identityTables(catalog)) {
    if (accountGroups.some(g => g.table === it.table) || memberships.some(m => m.table === it.table)) continue;
    accountGroups.push({ table: it.table, userCol: it.authCol, groupCol: it.idCol, group: it.table, groupPk: it.idCol, account: true, identity: true });
  }
  const groupTables = new Set([...memberships, ...accountGroups].map(m => m.group));
  const texts = authText(catalog);
  const mentions = (...words) => texts.some(s => words.every(w => new RegExp(`\\b${w}\\b`, 'i').test(s)));
  // The access rules compare this column to a privileged value (role = 'admin',
  // role in ('owner', 'editor'), 'admin' = any(roles)): a chat message's
  // role ('user' / 'assistant') or auth.role() is not a privilege.
  const PRIV = "(admin|super_?admin|owner|staff|moderator|manager|editor|superuser|root|support|operator)";
  const comparesPrivilege = (table, col) => texts.some(s => new RegExp(`\\b${table}\\b`, 'i').test(s) || true) && texts.some(s =>
    new RegExp(`(?<![.\\w])(\\w+\\.)?"?${col}"?\\s*(=|<>|!=|in\\s*\\(|=\\s*any\\s*\\()[^;]{0,80}'${PRIV}'`, 'i').test(s)
    || new RegExp(`'${PRIV}'[^;]{0,40}(=|in)\\s*(any\\s*\\()?\\s*(\\w+\\.)?"?${col}"?\\b`, 'i').test(s)
    || new RegExp(`(?<![.\\w])(\\w+\\.)?"?${col}"?\\s+is\\s+true`, 'i').test(s) || new RegExp(`(?<![.\\w])(\\w+\\.)?"?${col}"?\\s*=\\s*true`, 'i').test(s));

  // A table keyed by the auth user id (profiles.id references auth.users).
  const profileLike = (table, col) => {
    const p = catalog.find(x => x.name === table);
    return !!p && p.pk.length === 1 && p.pk[0] === col && userFkCols(p).includes(col);
  };
  const schema = catalog.map(t => {
    const names = t.columns.map(c => c.name);
    const o = overrides[t.name] || {};
    const fk = userFkCols(t);
    const autoMembership = memberships.find(m => m.table === t.name);
    const isMembership = manifest.membership !== undefined ? manifest.membership === t.name : !!autoMembership;

    // The column the table's own policies compare with auth.uid() is the
    // owner, whatever its foreign keys say (accounts.id set to the user id by a
    // signup trigger, next to an audit column created_by).
    const polText = (t.policies || []).map(p => p.text).join(' ');
    const own = `(${t.name}\\.)?`;
    const uidCmp = c => new RegExp(`auth\\.uid\\(\\)(\\s+AS\\s+\\w+)?\\s*\\)?\\s*=\\s*(?<![\\w.])${own}"?${c}"?(?![\\w"])|(?<![\\w.])${own}"?${c}"?\\s*=\\s*\\(?\\s*(select\\s+)?auth\\.uid\\(\\)`, 'i').test(polText);
    const guessed = fk[0] || OWNER_NAMES.find(n => isUuidCol(t, n) && !t.fks.some(f => f.col === n && f.refSchema === 'public'))
        // user_id references profiles(id), and profiles.id is the auth user id:
        // still the user's own id.
        || t.fks.find(f => f.refSchema === 'public' && f.refTable !== t.name && isUuidCol(t, f.col) && profileLike(f.refTable, f.refCol))?.col
        || null;
    // Third-party sign-in (Clerk and the like): a text column compared with the
    // token's subject, auth.jwt() ->> 'sub'. The subject is the user's id.
    const SUB = `(coalesce\\(\\s*)?(\\(\\s*)*(select\\s+)?auth\\.jwt\\(\\)(\\s+as\\s+\\w+)?\\s*\\)?\\s*->>\\s*'sub'(::text)?`;
    const subCmp = c => new RegExp(`(?<![\\w.])${own}"?${c}"?\\s*=\\s*\\(?\\s*${SUB}|${SUB}\\s*\\)?\\s*=\\s*${own}"?${c}"?(?![\\w"])`, 'i').test(polText);
    const byPolicy = guessed && uidCmp(guessed) ? null : (t.columns.find(c => c.type === 'uuid' && uidCmp(c.name))
      || t.columns.find(c => /^(text|character varying)/.test(c.type) && subCmp(c.name)))?.name;
    // An audit column (added_by_user_id, approved_by) records who acted, not
    // whose row it is, unless the table's own rules use it as the owner.
    const auditOnly = guessed && /(^|_)(added|removed|approved|reviewed|invited|updated|deleted|modified|created|assigned)_by(_user)?(_id)?$/i.test(guessed) && !uidCmp(guessed) && !new RegExp(`\\b${guessed}\\b`).test(polText);
    const owner = o.owner !== undefined ? o.owner : (byPolicy || (auditOnly ? null : guessed));

    let tenant = o.tenant !== undefined ? o.tenant : null;
    let tenantVia = null;
    if (tenant === null && o.tenant === undefined) {
      if (autoMembership) { tenant = autoMembership.groupCol; tenantVia = autoMembership; }
      else {
        const toGroup = t.fks.find(f => f.refSchema === 'public' && groupTables.has(f.refTable) && f.refTable !== t.name);
        if (toGroup) { tenant = toGroup.col; tenantVia = [...memberships, ...accountGroups].find(m => m.group === toGroup.refTable); }
        else if (groupTables.has(t.name) && !owner && t.pk.length === 1) {
          tenant = t.pk[0]; tenantVia = memberships.find(m => m.group === t.name);
        } else tenant = TENANT_NAMES.find(n => isUuidCol(t, n)) || null;
      }
    }

    // PK columns with defaults are left out of test inserts.
    // Identity and generated columns can't be written either.
    const generated = t.columns.filter(c => (c.hasDefault && t.pk.includes(c.name)) || c.identity || c.generated).map(c => c.name);

    // A user-level role column that the app's access rules actually read.
    let role = null;
    if (owner && !isMembership && !o.noRoleCheck) {
      for (const c of t.columns) {
        if (!(ROLE_COL.test(c.name) || (ADMIN_BOOL_COL.test(c.name) && c.category === 'B'))) continue;
        const rv = roleValues(c);
        if (!rv || !mentions(t.name, c.name)) continue;
        if (c.category !== 'B' && (c.values || []).some(v => /^(assistant|system|tool|function)$/i.test(v))) continue;
        // Free text: only when the rules compare it to a privileged value. A fixed
        // list (enum or check) that includes one is evidence on its own.
        if (c.category !== 'B' && !(c.values || []).length && !comparesPrivilege(t.name, c.name)) continue;
        const ownerUnique = (t.pk.length === 1 && t.pk[0] === owner) || t.uniques.some(u => u.length === 1 && u[0] === owner);
        role = { col: c.name, admin: rv.admin, low: rv.low, values: c.values || null, insertable: !ownerUnique };
        break;
      }
    }
    const roleTable = !!role && ROLE_TABLE.test(t.name);

    // Money and status columns on a row its owner can edit, in a table that a
    // privileged role (staff, admin) also manages: the owner shouldn't set them.
    const manager = (t.policies.map(p => p.text).join(' ') + ' ' + (t.triggerText || '')).match(/\b((?:public\.)?(?:is_(?!anonymous|authori[sz]ed|approved|allowed|member|active|verified|invited|onboarded|logged|signed|authenticated)\w+|has_role|has_any_role|current_user_role|get_user_role)\s*\((?:[^()]|\([^()]*\))*\))|\b(admin|staff|manager|moderator)\b/i);
    // Nobody but the owner can see or touch these rows: every policy is just
    // "owner = auth.uid()". Then a status or a count on them is the owner's
    // own business (a personal CRM's order status, a habit tracker's tally).
    const uidRe = `\\(?\\s*(select\\s+)?auth\\.uid\\(\\)(\\s+as\\s+\\w+)?\\s*\\)?(::\\w+)?`;
    const ownRe = owner ? new RegExp(`\\(?(\\w+\\.)?"?${owner}"?\\)?(::\\w+)?\\s*=\\s*${uidRe}|${uidRe}\\s*=\\s*\\(?(\\w+\\.)?"?${owner}"?\\)?(::\\w+)?`, 'gi') : null;
    const ownerOnly = !!owner && t.policies.length > 0 && t.policies.every(p => !/\bto\s+anon\b/i.test(p.roles || '')
      && /^[\s()]*((and|or)[\s()]*)*$/i.test(String(p.text || '').replace(ownRe, ' ').replace(/\b(and|or)\b/gi, ' and ').trim()));
    let tamper = [];
    if (owner && !isMembership) {
      for (const c of t.columns) {
        if (c.name === owner || t.pk.includes(c.name) || c.generated || c.identity) continue;
        // Counters and verification marks (helpful_count, verified_purchase) are
        // never the author's to set, staff or not; money and status only when a
        // privileged role manages the table.
        const counter = (c.category === 'N' && COUNTER.test(c.name)) || (c.category === 'B' && /verified/i.test(c.name));
        // Buyer-side status (an order, a payment, a subscription) is the
        // business's to set even when no staff role is written down.
        const buyerStatus = /order|payment|subscription|checkout|cart/i.test(t.name) && ((c.category === 'S' || c.enum) && STATUS.test(c.name) || (c.category === 'B' && PAID_BOOL.test(c.name)));
        // A paid / premium / verified flag or a credit balance is the business's
        // to set on any table, even one only its owner can see: a user marking
        // their own account premium or topping up their own credits.
        const trust = TRUST_FIELD.test(c.name) && (c.category === 'B' || c.category === 'N' || c.category === 'S' || c.enum);
        if (!manager && !counter && !buyerStatus && !trust) continue;
        const v = counter && c.category === 'N' ? '99999' : tamperValue(c);
        const kind = counter ? 'counter' : MONEY.test(c.name) || BALANCE.test(c.name) ? 'money' : 'status';
        if (v !== null) tamper.push({ col: c.name, value: v, kind, defaultExpr: c.defaultExpr || null });
      }
    }
    // Membership role a member could raise on their own row.
    let memberRole = null;
    if (isMembership) {
      const rc = t.columns.find(c => ROLE_COL.test(c.name) || (ADMIN_BOOL_COL.test(c.name) && c.category === 'B'));
      const rv = rc && roleValues(rc);
      if (rv) memberRole = { col: rc.name, admin: rv.admin, low: rv.low, top: highestRole(rc) };
    }

    // One row per user (profiles keyed by the user id): the row already exists,
    // usually made by a signup trigger, so users don't need to insert it.
    const oneRowPerUser = !!owner && ((t.pk.length === 1 && t.pk[0] === owner) || t.uniques.some(u => u.length === 1 && u[0] === owner));
    // Row security on with no policies at all blocks every ordinary user. On a
    // server-managed table (an OAuth token store, a Stripe mirror, an
    // integration/sync table) that's intended — the backend writes it with the
    // service role. On a plain content table it's the classic lock-out bug, so
    // leave the owner checks in place to catch it.
    const serverManaged = /(^|_)(oauth|token|tokens|credential|credentials|secret|secrets|webhook|stripe|billing|integration|integrations|sync|gcal|gcal_accounts|calendar_sync|refresh|access_token|provider_accounts?)(_|$)/i.test(t.name);
    const lockedNoPolicy = t.rls && (t.policies || []).length === 0 && serverManaged;
    const defaultOps = (roleTable || lockedNoPolicy) ? [] : isMembership ? ['read'] : oneRowPerUser ? ['read', 'update'] : ['read', 'insert', 'update'];
    return {
      name: t.name,
      rls: t.rls,
      policyCount: t.policies.length,
      columns: names,
      colTypes: Object.fromEntries(t.columns.map(c => [c.name, c.type])),
      generated,
      // Columns the database fills in itself (timestamps, flags a trigger sets):
      // a new row from the app leaves them out.
      defaulted: t.columns.filter(c => c.hasDefault).map(c => c.name),
      numeric: t.columns.filter(c => c.category === 'N').map(c => c.name),
      ownerOnly,
      // Columns whose value decides which rule applies to a row (channel_type,
      // status, is_draft): the other values to try before calling a read broken.
      nullableCols: t.columns.filter(c => !c.notNull && !c.generated).map(c => c.name),
      variantCols: t.columns.filter(c => !c.generated && ((c.values?.length && c.values.length <= 12) || c.category === 'B'))
        .map(c => ({ name: c.name, values: c.category === 'B' ? ['true', 'false'] : c.values })),
      stateCols: t.columns.filter(c => !c.notNull && /^(deleted_at|archived_at|is_deleted|deleted|archived|is_archived|hidden|is_hidden|cancelled_at|canceled_at|completed_at|is_completed|done|trashed_at|removed_at)$/i.test(c.name) && (c.category === 'B' || c.category === 'D'))
        .map(c => ({ name: c.name, bool: c.category === 'B' })),
      owner,
      tenant,
      tenantVia,
      publicRead: !!o.publicRead || matches(manifest.publicTables, t.name),
      sharedRead: !!o.sharedRead || matches(manifest.sharedTables, t.name),
      legitOps: o.legitOps || defaultOps,
      legitOpsFromManifest: !!o.legitOps,
      policies: t.policies,
      oneRowPerUser,
      uniques: t.uniques,
      fks: t.fks,
      membership: isMembership,
      role,
      tamper,
      managerCheck: manager ? (manager[1] || null) : null,
      memberRole,
      skip: !!o.skip,
      fks: t.fks,
      pk: t.pk,
      // Columns in a unique constraint that a copied row must change to be insertable.
      freshen: [...new Set([...t.uniques, ...(generated.some(g => t.pk.includes(g)) ? [] : [t.pk])].flat())]
        .map(n => t.columns.find(c => c.name === n))
        .filter(c => c && !generated.includes(c.name) && !t.fks.some(f => f.col === c.name) && !c.values && !c.enum && ['S', 'N', 'U'].includes(c.category))
        .map(c => ({ name: c.name, category: c.category })),
    };
  });

  await resolveKeys(db, schema, catalog);

  // Tables whose rows block a delete of this table's rows (ON DELETE RESTRICT or
  // NO ACTION), deepest first: a delete attack clears them first, so row level
  // security alone decides the result instead of a foreign-key error.
  const refs = (await db.query(`
    select tc.relname as child, pc.relname as parent, con.confdeltype as action
    from pg_constraint con
    join pg_class tc on tc.oid = con.conrelid join pg_namespace tn on tn.oid = tc.relnamespace
    join pg_class pc on pc.oid = con.confrelid join pg_namespace pn on pn.oid = pc.relnamespace
    where con.contype = 'f' and con.confdeltype in ('a', 'r', 'c') and tn.nspname = 'public' and pn.nspname = 'public'
      and tc.oid <> pc.oid`)).rows;
  // Follow ON DELETE CASCADE children too: deleting a project cascades to its
  // tasks, and a task's share link may be what blocks.
  const blockers = (name, seen = new Set([name])) => {
    const out = [];
    for (const r of refs.filter(r => r.parent === name && !seen.has(r.child))) {
      seen.add(r.child);
      out.push(...blockers(r.child, seen));
      if (r.action !== 'c') out.push(r.child);
    }
    return out;
  };
  for (const t of schema) {
    const b = blockers(t.name);
    t.deleteSetup = b.length ? [...new Set(b)].map(c => `delete from public."${c.replace(/"/g, '""')}";`).join(' ') : null;
  }
  // Only expect the owner to insert or update when some policy for that action
  // is written in terms of the owner (their key column or auth.uid()). Orders
  // only staff may update, or tables filled by the server, aren't "broken" when
  // a customer can't write them; and telling an agent they are would push it to
  // open them up.
  for (const t of schema) {
    if (t.legitOpsFromManifest || !t.policies.length) continue;
    // Written in terms of this table's own ownership column (user_id = auth.uid(),
    // is_team_member(team_id), a parent lookup on project_id). A bare role check
    // (is_staff(), an admin-only audit log) doesn't make every user a writer.
    const ownerish = p => !!t.key && new RegExp(`\\b${t.key}\\b`).test(p.text);
    const intended = cmd => t.policies.some(p => (p.cmd === cmd || p.cmd === 'ALL') && ownerish(p));
    // Reading is expected too, unless every read policy is a staff/admin check
    // that never mentions the row's owner (an admin-only audit log).
    const reads = t.policies.filter(p => p.cmd === 'SELECT' || p.cmd === 'ALL');
    const staffOnly = p => /admin|staff|moderator|manager|is_[a-z_]+\s*\(|has_role/i.test(p.text) && !ownerish(p);
    // Or unless every read policy shows only published rows through the parent
    // (comments visible on published recipes): then hiding a comment on an
    // unpublished recipe is the design, not a lock-out.
    const publishedOnly = p => !ownerish(p) && /publish|is_public|visibility|visible/i.test(p.text);
    const readIntended = !reads.length || !reads.every(p => staffOnly(p) || publishedOnly(p));
    t.legitOps = t.legitOps.filter(op => op === 'read' ? readIntended : intended(op.toUpperCase()));
  }
  // What the app granted signed-in users. A table (or command) they were never
  // granted, or had revoked, is closed to them on purpose: not "broken". A table
  // with no policies that the app's own security-definer functions write is
  // reached through those functions only (start_round(), take_quota()).
  const definerSrc = (await db.query(`select string_agg(p.prosrc, ' ') as s from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.prosecdef`)).rows[0]?.s || '';
  for (const t of schema) {
    if (t.legitOpsFromManifest) continue;
    const priv = (await db.query(`select has_table_privilege('authenticated', $1, 'SELECT') as s, has_table_privilege('authenticated', $1, 'INSERT') as i,
      has_table_privilege('authenticated', $1, 'UPDATE') as u, has_table_privilege('authenticated', $1, 'DELETE') as d`, [`public."${t.name.replace(/"/g, '""')}"`]).catch(() => ({ rows: [{}] }))).rows[0];
    const granted = { read: priv.s !== false, insert: priv.i !== false, update: priv.u !== false, delete: priv.d !== false };
    t.granted = granted;
    const anonAny = (await db.query(`select has_table_privilege('anon', $1, 'SELECT') or has_table_privilege('anon', $1, 'INSERT') or has_table_privilege('anon', $1, 'UPDATE') or has_table_privilege('anon', $1, 'DELETE') as a`, [`public."${t.name.replace(/"/g, '""')}"`]).catch(() => ({ rows: [{ a: true }] }))).rows[0].a;
    // Neither visitors nor signed-in users can touch it through the API at all.
    t.noApiAccess = !anonAny && !Object.values(granted).some(Boolean);
    t.legitOps = (t.legitOps || []).filter(op => granted[op] !== false);
    if (!Object.values(granted).some(Boolean)) t.serverOnly = true;
    if (t.rls && !(t.policies || []).length && new RegExp(`\\b(insert\\s+into|update|delete\\s+from)\\s+(public\\.)?"?${t.name}"?\\b`, 'i').test(definerSrc)) { t.legitOps = []; t.serverOnly = true; }
    // Column-level grants: the owner-edit check writes a column they may update.
    if (t.legitOps.includes('update') && t.key) {
      const cols = (await db.query(`select column_name as c from information_schema.column_privileges where table_schema = 'public' and table_name = $1 and grantee = 'authenticated' and privilege_type = 'UPDATE'`, [t.name])).rows.map(r => r.c);
      const all = t.columns.length;
      if (cols.length && cols.length < all && !cols.includes(t.key)) t.updateCol = cols.find(c => !t.pk.includes(c)) || cols[0];
      if (!cols.length && priv.u === false) t.legitOps = t.legitOps.filter(o => o !== 'update');
    }
  }
  // Declarations, for views (which aren't in the table list) and later checks.
  schema.manifest = manifest;
  return schema;
}

// Decide which column and which values identify user A's and user B's rows.
async function resolveKeys(db, schema, catalog) {
  const one = async (sql, params) => (await db.query(sql, params)).rows[0]?.v ?? null;
  async function groupOf(m, uid) {
    if (!m) return null;
    return one(`select ${q(m.groupCol)}::text as v from public.${q(m.table)} where ${userMatch(catalog, m.table, m.userCol)} limit 1`, [uid]);
  }
  for (const t of schema) {
    if (t.tenant) {
      // The placeholder team ids are uuids; a numeric team column gets none.
      const uuidTenant = (t.colTypes?.[t.tenant] || 'uuid') === 'uuid';
      const realA = await groupOf(t.tenantVia, IDS.A);
      // No team of A's could be found: the placeholder id belongs to nobody,
      // so "A can't use A's team data" would prove nothing.
      t.tenantPlaceholder = realA == null && !!t.tenantVia;
      t.tenantA = realA ?? (uuidTenant ? IDS.ORG_A : null);
      t.tenantB = (await groupOf(t.tenantVia, IDS.B)) ?? (uuidTenant ? IDS.ORG_B : null);
    }
    if (t.owner) Object.assign(t, { key: t.owner, keyA: IDS.A, keyB: IDS.B, keyKind: 'owner' });
    else if (!t.tenant) {
      // Owned by email: the rules compare a column with the sign-in email.
      const txt = (t.policies || []).map(p => p.text).join(' ');
      const m = txt.match(/(?:lower\()?\(?"?(\w*email\w*)"?\)?\s*=\s*(?:lower\()?\s*\(?\s*(?:coalesce\()?\s*\(?\s*\(?auth\.jwt\(\)\s*->>\s*'email'/i);
      if (m && t.columns.includes(m[1])) { Object.assign(t, { key: m[1], keyA: EMAILS[IDS.A], keyB: EMAILS[IDS.B], keyKind: 'email' }); continue; }
    }
    else if (t.tenant) Object.assign(t, { key: t.tenant, keyA: t.tenantA, keyB: t.tenantB, keyKind: 'tenant' });
  }
  // Parent chains: a table with no owner or tenant of its own belongs to whoever owns its parent row.
  for (let pass = 0; pass < 4; pass++) {
    for (const t of schema.filter(x => !x.key)) {
      for (const f of t.fks.filter(f => f.refSchema === 'public' && f.refTable !== t.name)) {
        const p = schema.find(s => s.name === f.refTable);
        if (!p?.key) continue;
        // Prefer the parent row that has children here: an app's own trigger may
        // have made another parent for the same user (a document per upload).
        const pick = v => one(`select p.${q(f.refCol)}::text as v from public.${q(p.name)} p
          where p.${q(p.key)} = $1 order by exists (select 1 from public.${q(t.name)} c where c.${q(f.col)} = p.${q(f.refCol)}) desc limit 1`, [v]);
        const A = await pick(p.keyA);
        const B = await pick(p.keyB);
        if (A == null) continue;
        Object.assign(t, { key: f.col, keyA: A, keyB: B, keyKind: 'parent', parent: p.name, tenantPlaceholder: !!p.tenantPlaceholder });
        break;
      }
    }
  }
}
