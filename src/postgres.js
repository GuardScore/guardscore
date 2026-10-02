// Generic Postgres RLS attack engine — "any Postgres app", not just Supabase.
//
// The Supabase engine assumes Supabase's roles and auth.uid()/JWT claims. Most
// non-Supabase Postgres apps (PostgREST, hand-rolled RLS, Prisma-with-RLS) instead
// carry the caller's identity in a GUC set per request — current_setting('app.user_id')
// or similar — and enforce it with RLS policies. This engine attacks that pattern:
// it builds a private copy from the migrations, reads the REAL policies from the
// catalog (pg_policies), seeds two users, and attacks as a non-owner role so RLS
// actually applies — anonymous (no identity set) and as another user — then confirms
// the legitimate owner still works. Same verdicts, same Guard Score caps, same proof
// receipts as every other engine.
//
// It is native Postgres (PGlite), so current_setting / set_config / RLS behave
// exactly as on a real server; we never re-implement policy evaluation.

import { newEngine } from './db.js';

const A = '00000000-0000-4000-8000-0000000000a1';
const B = '00000000-0000-4000-8000-0000000000b1';
const APP_ROLE = 'vc_app_user';

const EXPLAIN = {
  anon_read: 'An unauthenticated caller (no identity set) can read rows in this table — RLS is on but a policy allows everyone.',
  anon_write: 'An unauthenticated caller can change or delete rows in this table.',
  cross_user_read: 'One user can read another user’s rows — the policy does not scope reads to the caller’s identity.',
  cross_user_write: 'One user can change or delete another user’s rows.',
  no_rls: 'Row level security is not enabled on this table, so the application role can read and write every row.',
};
const FIX = {
  scope: (t, col, guc) => `Scope the policy to the caller's identity:\n  alter table ${t} enable row level security;\n  create policy ${t}_owner on ${t} using (${col} = current_setting('${guc || 'app.user_id'}')::uuid)\n    with check (${col} = current_setting('${guc || 'app.user_id'}')::uuid);`,
  enable: t => `Enable RLS and add an owner-scoped policy:\n  alter table ${t} enable row level security;\n  -- then a policy that compares an owner column to your per-request identity GUC`,
};

async function q(db, sql, params = []) { try { return (await db.query(sql, params)).rows; } catch { return []; } }

// Find the identity GUC the app uses and, per RLS table, the owner column.
async function introspect(db) {
  const pols = await q(db, `select tablename, qual, with_check, cmd, roles from pg_policies where schemaname = 'public'`);
  const gucs = new Set();
  for (const p of pols) for (const expr of [p.qual, p.with_check]) {
    let m; const re = /current_setting\(\s*'([^']+)'/g;
    while (expr && (m = re.exec(expr))) gucs.add(m[1]);
  }
  const guc = [...gucs][0] || null;
  const rlsTables = (await q(db, `select c.relname as t from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity`)).map(r => r.t);
  const allTables = (await q(db, `select c.relname as t from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'public' and c.relkind = 'r'`)).map(r => r.t);
  // owner column per table: a uuid column named like an owner, preferring one that appears in a policy qual.
  const ownerOf = {};
  for (const t of allTables) {
    const cols = await q(db, `select column_name as c, data_type as d, is_nullable as n, column_default as def from information_schema.columns where table_schema='public' and table_name=$1`, [t]);
    const pol = pols.find(p => p.tablename === t);
    let owner = null;
    if (pol) { const m = /(\w+)\s*=\s*current_setting|current_setting\([^)]*\)\s*(?:::[\w ]+)?\s*=\s*(\w+)/.exec((pol.qual || '') + ' ' + (pol.with_check || '')); owner = m && (m[1] || m[2]); }
    if (!owner) owner = (cols.find(c => /^(user_id|owner_id|owner|author_id|account_id|created_by|uid)$/i.test(c.c)) || {}).c;
    ownerOf[t] = { owner, cols };
  }
  return { guc, rlsTables, allTables, ownerOf, policies: pols };
}

// Insert a row owned by `who` (as the table owner, bypassing RLS), filling NOT NULL
// columns with type-appropriate dummies. Best-effort: returns true if a row landed.
async function seedRow(db, t, info, who) {
  const owner = info.owner;
  if (!owner) return false;
  const names = [], vals = [];
  for (const c of info.cols) {
    if (c.c === owner) { names.push(`"${owner}"`); vals.push(`'${who}'`); continue; }
    if (c.n === 'YES' || c.def != null) continue; // nullable or has a default → let the DB fill it
    // required column with no default: dummy by type
    names.push(`"${c.c}"`);
    vals.push(dummy(c.d));
  }
  const withCols = `insert into public."${t}" (${names.join(',')}) values (${vals.join(',')})`;
  const ok = await db.exec(withCols).then(() => true, () => false);
  if (ok) return true;
  // retry letting all defaults apply, only setting the owner
  return db.exec(`insert into public."${t}" ("${owner}") values ('${who}')`).then(() => true, () => false);
}
const dummy = d => /uuid/.test(d) ? `'00000000-0000-4000-8000-0000000000ff'` : /(int|numeric|double|real|decimal)/.test(d) ? '1' : /bool/.test(d) ? 'false' : /(timestamp|date)/.test(d) ? 'now()' : /json/.test(d) ? `'{}'` : /(text|char|citext)/.test(d) ? `'x'` : `'x'`;

// Run one statement as the app role with an optional identity GUC, always rolled back.
async function runPg(db, { guc, id }, sql) {
  await db.exec('begin');
  try {
    await db.exec(`set local role ${APP_ROLE}`);
    if (guc) await db.query(`select set_config($1, $2, true)`, [guc, id ?? '']);
    const res = await db.query(sql);
    return { ok: true, rows: res.rows, affected: res.affectedRows ?? 0 };
  } catch (e) { return { ok: false, error: e.message }; }
  finally { await db.exec('rollback').catch(() => {}); } // rollback also reverts the transaction-local SET ROLE
}

export async function verifyPostgres({ sql, migrations, projectDir } = {}) {
  let mig = migrations;
  if (!mig && projectDir) { const { loadMigrations } = await import('./project.js'); mig = loadMigrations(projectDir).sql; }
  if (!mig && sql) mig = [sql];
  const db = newEngine();
  for (const part of (mig || [])) { try { await db.exec(part); } catch { /* best-effort per statement below */ } }

  const info = await introspect(db);
  // create the non-owner application role and grant it table access (RLS applies on top)
  await db.exec(`do $$ begin if not exists (select from pg_roles where rolname='${APP_ROLE}') then create role ${APP_ROLE} nologin; end if; end $$;`).catch(() => {});
  await db.exec(`grant usage on schema public to ${APP_ROLE}`).catch(() => {});
  await db.exec(`grant select, insert, update, delete on all tables in schema public to ${APP_ROLE}`).catch(() => {});

  const checks = [];
  const leaked = [];
  const broken = [];
  const add = (arr, o) => { arr.push(o); return o; };

  for (const t of info.allTables) {
    const meta = info.ownerOf[t];
    if (!meta.owner) continue; // no owner column → can't model per-user ownership
    const T = `public."${t}"`;
    const seededA = await seedRow(db, t, meta, A);
    const seededB = await seedRow(db, t, meta, B);
    if (!seededB) continue; // couldn't create a victim row → not tested

    const rlsOn = info.rlsTables.includes(t);
    if (!rlsOn) {
      const r = await runPg(db, {}, `select count(*)::int as n from ${T}`);
      const observed = `${r.rows?.[0]?.n ?? 0} row(s) visible to the app role with RLS off`;
      const c = add(leaked, { id: `${t}.no_rls`, table: `public.${t}`, class: 'no_rls', severity: 'critical', what: EXPLAIN.no_rls, fix: FIX.enable(t), proof: { actor: 'app role', op: `select ${t}`, observed } });
      checks.push(c); continue;
    }

    // anonymous (no identity GUC) read of the victim's rows
    const anon = await runPg(db, { guc: info.guc, id: null }, `select count(*)::int as n from ${T} where "${meta.owner}" = '${B}'`);
    if (anon.ok && (anon.rows?.[0]?.n ?? 0) > 0) add(leaked, checks[checks.push({ id: `${t}.anon.read`, table: `public.${t}`, class: 'anon_read', severity: 'critical', what: EXPLAIN.anon_read, fix: FIX.scope(t, meta.owner, info.guc), proof: { actor: 'anonymous', op: `select ${t}`, observed: `read ${anon.rows[0].n} of the victim’s row(s) with no identity set` } }) - 1]);

    // cross-user read: identity = A, read B's rows
    const xr = await runPg(db, { guc: info.guc, id: A }, `select count(*)::int as n from ${T} where "${meta.owner}" = '${B}'`);
    if (xr.ok && (xr.rows?.[0]?.n ?? 0) > 0) add(leaked, checks[checks.push({ id: `${t}.cross.read`, table: `public.${t}`, class: 'cross_user_read', severity: 'critical', what: EXPLAIN.cross_user_read, fix: FIX.scope(t, meta.owner, info.guc), proof: { actor: 'user A', op: `select ${t} where ${meta.owner}=B`, observed: `read ${xr.rows[0].n} of user B’s row(s)` } }) - 1]);

    // cross-user write: identity = A, delete B's rows
    const xw = await runPg(db, { guc: info.guc, id: A }, `delete from ${T} where "${meta.owner}" = '${B}'`);
    if (xw.ok && xw.affected > 0) add(leaked, checks[checks.push({ id: `${t}.cross.write`, table: `public.${t}`, class: 'cross_user_write', severity: 'critical', what: EXPLAIN.cross_user_write, fix: FIX.scope(t, meta.owner, info.guc), proof: { actor: 'user A', op: `delete ${t} where ${meta.owner}=B`, observed: `deleted ${xw.affected} of user B’s row(s)` } }) - 1]);

    // legit: identity = A can read A's own rows
    const legit = await runPg(db, { guc: info.guc, id: A }, `select count(*)::int as n from ${T} where "${meta.owner}" = '${A}'`);
    if (!(legit.ok && (legit.rows?.[0]?.n ?? 0) > 0)) add(broken, checks[checks.push({ id: `${t}.legit.read`, table: `public.${t}`, class: 'breaks_app', severity: 'high', what: 'The legitimate owner could not read their own rows — the policy locks real users out.', fix: 'Loosen the policy so the owner (owner column = the caller identity) is allowed.', proof: { actor: 'user A', op: `select own ${t}`, observed: legit.ok ? 'returned 0 of their own rows' : (legit.error || 'denied') } }) - 1]);
  }

  await db.close?.();

  const critical = leaked.length;
  const findings = [...leaked, ...broken];
  let verdict, guardScore;
  if (leaked.length) { verdict = 'unsafe'; guardScore = Math.max(12, 59 - 8 * (leaked.length - 1)); }
  else if (broken.length) { verdict = 'breaks_app'; guardScore = Math.max(70, 79 - 3 * (broken.length - 1)); }
  else if (info.allTables.length) { verdict = 'safe'; guardScore = 100; }
  else { verdict = 'untested'; guardScore = null; }

  return {
    stack: 'postgres',
    verdict, guardScore,
    identityGuc: info.guc,
    findings,
    counts: { critical, high: broken.length, warning: 0 },
    attacks: { run: checks.filter(c => c.class !== 'breaks_app').length + leaked.length, blocked: 0 },
    note: info.guc ? undefined : 'No per-request identity GUC (current_setting) was found in the policies; only RLS-off tables could be judged. If this is a Supabase app, use the Supabase engine.',
  };
}
