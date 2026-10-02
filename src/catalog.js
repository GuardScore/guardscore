// One read of the Postgres catalog for the public schema: columns with types,
// defaults, enum and CHECK value lists, primary keys, foreign keys, and the text
// of every policy and public function. Introspection and automatic fixtures both
// work from this.

export async function loadCatalog(db) {
  const tables = (await db.query(`
    select c.oid::int as oid, c.relname as name, c.relrowsecurity as rls
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'r'
    order by c.relname`)).rows;

  const cols = (await db.query(`
    select c.relname as table_name, a.attnum as num, a.attname as name,
           format_type(a.atttypid, a.atttypmod) as type, t.typtype as typtype, t.typcategory as category,
           a.attnotnull as notnull, a.atthasdef as hasdef, a.attidentity as identity, a.attgenerated as generated,
           pg_get_expr(d.adbin, d.adrelid) as default_expr,
           (select array_agg(e.enumlabel order by e.enumsortorder) from pg_enum e where e.enumtypid = a.atttypid) as enum_values
    from pg_attribute a
    join pg_class c on c.oid = a.attrelid
    join pg_namespace n on n.oid = c.relnamespace
    join pg_type t on t.oid = a.atttypid
    left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum
    where n.nspname = 'public' and c.relkind = 'r' and a.attnum > 0 and not a.attisdropped
    order by c.relname, a.attnum`)).rows;

  const cons = (await db.query(`
    select cl.relname as table_name, con.contype as type, con.conname as name,
           (select array_agg(a.attname order by k.ord) from unnest(con.conkey) with ordinality k(n, ord)
              join pg_attribute a on a.attrelid = con.conrelid and a.attnum = k.n) as cols,
           rn.nspname as ref_schema, ref.relname as ref_table,
           (select array_agg(a.attname order by k.ord) from unnest(con.confkey) with ordinality k(n, ord)
              join pg_attribute a on a.attrelid = con.confrelid and a.attnum = k.n) as ref_cols,
           pg_get_constraintdef(con.oid) as def
    from pg_constraint con
    join pg_class cl on cl.oid = con.conrelid
    join pg_namespace n on n.oid = cl.relnamespace
    left join pg_class ref on ref.oid = con.confrelid
    left join pg_namespace rn on rn.oid = ref.relnamespace
    where n.nspname = 'public' and con.contype in ('p', 'u', 'f', 'c')`)).rows;

  // Unique indexes created without a constraint count as unique too.
  const uidx = (await db.query(`
    select cl.relname as table_name,
           (select array_agg(a.attname) from unnest(i.indkey) k(n) join pg_attribute a on a.attrelid = i.indrelid and a.attnum = k.n) as cols
    from pg_index i join pg_class cl on cl.oid = i.indrelid join pg_namespace n on n.oid = cl.relnamespace
    where n.nspname = 'public' and i.indisunique and not i.indisprimary`)).rows;

  const policies = (await db.query(`
    select schemaname, tablename, policyname, cmd, array_to_string(roles, ',') as roles, coalesce(qual, '') || ' ' || coalesce(with_check, '') as text
    from pg_policies`)).rows;
  const triggers = (await db.query(`
    select c.relname as table_name, p.prosrc as src from pg_trigger tg join pg_class c on c.oid = tg.tgrelid
    join pg_namespace n on n.oid = c.relnamespace join pg_proc p on p.oid = tg.tgfoid
    where n.nspname = 'public' and not tg.tgisinternal`)).rows;
  const functions = (await db.query(`
    select p.proname as name, p.prosrc as src from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'`)).rows;

  const catalog = tables.map(t => {
    const c = cols.filter(x => x.table_name === t.name);
    const k = cons.filter(x => x.table_name === t.name);
    const pk = k.find(x => x.type === 'p')?.cols || [];
    // Expression indexes (unique on lower(email)) have no plain column list.
    const uniques = [...k.filter(x => x.type === 'u').map(x => x.cols), ...uidx.filter(x => x.table_name === t.name).map(x => x.cols)].filter(c => Array.isArray(c) && c.length && c.every(Boolean));
    const fks = k.filter(x => x.type === 'f' && x.cols.length === 1).map(x => ({
      col: x.cols[0], refSchema: x.ref_schema, refTable: x.ref_table, refCol: x.ref_cols[0],
    }));
    // Multi-column keys (tenant_id, seller_id) -> sellers (tenant_id, id): the
    // usual way a multi-tenant app keeps a child in its parent's team.
    const cfks = k.filter(x => x.type === 'f' && x.cols.length > 1 && x.ref_cols?.length === x.cols.length).map(x => ({
      cols: x.cols, refSchema: x.ref_schema, refTable: x.ref_table, refCols: x.ref_cols,
    }));
    const columns = c.map(x => ({
      name: x.name,
      type: x.type,
      enum: x.typtype === 'e',
      category: x.category,
      notNull: x.notnull,
      hasDefault: x.hasdef,
      defaultExpr: x.default_expr,
      identity: x.identity || '',
      generated: x.generated || '',
      values: x.enum_values || checkValues(k, x.name),
    }));
    return {
      name: t.name, rls: t.rls, columns, pk, uniques, fks, cfks,
      triggerText: triggers.filter(x => x.table_name === t.name).map(x => x.src || '').join('\n'),
      policies: policies.filter(p => p.schemaname === 'public' && p.tablename === t.name),
    };
  }).map((t, _i, all) => Object.assign(t, { _all: all, _policies: policies, _functions: functions }));
  return catalog;
}

// Values allowed by a single-column CHECK like  role in ('user', 'admin').
function checkValues(cons, col) {
  for (const c of cons.filter(x => x.type === 'c' && x.cols?.length === 1 && x.cols[0] === col)) {
    // Only an equality list is a list of allowed values; a regex, LIKE or
    // length check also contains quoted strings but they aren't values.
    if (/~|\blike\b|\bsimilar\b|length\(|char_length/i.test(c.def) || !/= ANY \(ARRAY\[|=\s*'/i.test(c.def)) continue;
    // A function of the column (jsonb_typeof(terms) = 'object') isn't a list of its values.
    if (new RegExp(`\\w+\\(\\s*"?${col}"?\\s*\\)`).test(c.def)) continue;
    const vals = [...c.def.matchAll(/'((?:[^']|'')*)'/g)].map(m => m[1].replace(/''/g, "'"));
    if (vals.length) return vals;
  }
  return null;
}

// Every policy (any schema) and every public function body, as searchable text.
export function authText(catalog) {
  const first = catalog[0];
  if (!first) return [];
  return [...first._policies.map(p => p.text), ...first._functions.map(f => f.src || '')];
}

export const USER_COL_NAMES = ['user_id', 'owner_id', 'author_id', 'created_by', 'profile_id', 'owner', 'creator_id'];
export const ROLE_COL = /^(role|user_role|app_role|account_role|account_type|user_type|access_level)$/i;
export const ADMIN_BOOL_COL = /^(is_)?(admin|staff|superuser|super_admin|superadmin|moderator)$/i;
const PRIVILEGED = /admin|owner|staff|manager|moderator|editor|super/i;

export function userFkCols(t) {
  return t.fks.filter(f => f.refSchema === 'auth' && f.refTable === 'users').map(f => f.col);
}

// Identity tables: the app keeps its own users table and maps the sign-in to
// it by a column the access rules compare with auth.uid()
// (select id from users where "authId" = auth.uid()). Other tables then point
// at that table's id, not at the sign-in id.
export function identityTables(catalog) {
  const texts = authText(catalog);
  const out = [];
  const esc = x => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  for (const t of catalog) {
    if (t.pk.length !== 1) continue;
    for (const c of t.columns) {
      if (c.name === t.pk[0] || userFkCols(t).includes(c.name) || !['U', 'S'].includes(c.category)) continue;
      const col = `\\(?(\\w+\\.)?"?${esc(c.name)}"?\\)?(::\\w+(\\s+varying)?)?`;
      const uid = `\\(?\\s*(select\\s+)?auth\\.uid\\(\\)\\s*\\)?(::text)?`;
      const from = `from\\s+(public\\.)?"?${esc(t.name)}"?(\\s+(as\\s+)?\\w+)?\\s+where\\s+[^;]{0,120}?`;
      const re = new RegExp(`${from}(${col}\\s*=\\s*${uid}|${uid}\\s*=\\s*${col}(?![\\w"]))`, 'i');
      if (texts.some(x => re.test(x))) { out.push({ table: t.name, authCol: c.name, idCol: t.pk[0] }); break; }
    }
  }
  return out;
}

// SQL that is true when column `col` of `table` names the signed-in user $1.
// Usually the column holds the sign-in id; when it points at the app's own
// users table (book_members.user_id -> users.id, users.auth_user_id =
// auth.uid()), go through that row.
export function userMatch(catalog, table, col, alias = '') {
  const t = catalog.find(x => x.name === table);
  const c = `${alias ? alias + '.' : ''}"${col.replace(/"/g, '""')}"`;
  const fk = t?.fks.find(f => f.col === col && f.refSchema === 'public' && f.refTable !== table);
  const ref = fk && catalog.find(x => x.name === fk.refTable);
  if (ref) {
    const authCol = userFkCols(ref).find(u => u !== fk.refCol) || identityTables(catalog).find(i => i.table === ref.name)?.authCol;
    if (authCol) return `${c} in (select "${fk.refCol}" from public."${ref.name}" where "${authCol}"::text = $1::text)`;
  }
  return `${c}::text = $1::text`;
}

// Membership tables link a user to a group (team, org, workspace, project...).
// user_<group> links a user to a group (user_teams); user_<thing> alone (user_cvs,
// user_job_statuses) is just that user's own data.
const MEMBERSHIP_NAME = /member|participant|collaborator|_users?$|^users?_(orgs?|organi[sz]ations?|teams?|workspaces?|groups?|projects?|compan(y|ies)|accounts?|households?|guilds?|clubs?|boards?|channels?|tenants?|families|family|classes|courses|spaces?|rooms?|circles?)$/i;
export function findMemberships(catalog) {
  const out = [];
  for (const t of catalog) {
    if (!MEMBERSHIP_NAME.test(t.name)) continue;
    const user = userFkCols(t)[0] || USER_COL_NAMES.find(n => t.columns.some(c => c.name === n));
    const group = t.fks.find(f => f.refSchema === 'public' && f.refTable !== t.name);
    if (user && group) out.push({ table: t.name, userCol: user, groupCol: group.col, group: group.refTable, groupPk: group.refCol });
  }
  return out;
}

// Pick the admin value and the least-privileged value for a role-like column.
// Roles an ordinary user of the app holds; staff-sounding ones they don't.
export const ORDINARY_ROLE = /^(user|member|customer|client|viewer|guest|student|patient|parent|basic|free|reader|buyer|learner|subscriber|fan|player|tenant|renter|athlete|driver|rider|traveler|employee|contributor|author|seller|vendor|host|attendee|participant|volunteer|family)$/i;
const STAFFISH = /operator|agent|support|staff|manager|coordinator|supervisor|teacher|instructor|coach|doctor|nurse|reception|cashier|dispatcher|analyst|accountant|auditor|developer|dev|ops|service|system|internal|employee_admin|lead|head|director|principal|organizer|organiser|vet|clinician|therapist/i;
export function roleValues(col) {
  if (col.category === 'B') return { admin: 'true', low: 'false' };
  const vals = col.values;
  if (vals && vals.length) {
    const admin = vals.find(v => /^admin$/i.test(v)) || vals.find(v => /super_?admin/i.test(v))
      || vals.find(v => /admin/i.test(v)) || vals.find(v => /owner/i.test(v)) || vals.find(v => PRIVILEGED.test(v));
    const low = vals.find(v => ORDINARY_ROLE.test(v)) || vals.find(v => !PRIVILEGED.test(v) && !STAFFISH.test(v));
    return admin && low ? { admin, low } : null;
  }
  if (col.category === 'S') return { admin: 'admin', low: 'user' };
  return null;
}

export function highestRole(col) {
  const vals = col.values;
  if (col.category === 'B') return 'true';
  if (!vals) return 'owner';
  return vals.find(v => /^owner$/i.test(v)) || vals.find(v => /admin/i.test(v)) || vals.find(v => PRIVILEGED.test(v)) || vals[0];
}
