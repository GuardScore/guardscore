// Creates an isolated Postgres instance (PGlite) with the Supabase shim,
// the app's migrations and deterministic fixtures. Every check gets its own
// isolated copy, which is the local equivalent of a Supabase branch.
import { PGlite } from '@electric-sql/pglite';
import { citext } from '@electric-sql/pglite/contrib/citext';
import { pgcrypto } from '@electric-sql/pglite/contrib/pgcrypto';
import { uuid_ossp } from '@electric-sql/pglite/contrib/uuid_ossp';
import { pg_trgm } from '@electric-sql/pglite/contrib/pg_trgm';
import { hstore } from '@electric-sql/pglite/contrib/hstore';
import { ltree } from '@electric-sql/pglite/contrib/ltree';
import { unaccent } from '@electric-sql/pglite/contrib/unaccent';
import { fuzzystrmatch } from '@electric-sql/pglite/contrib/fuzzystrmatch';
import { btree_gin } from '@electric-sql/pglite/contrib/btree_gin';
import { btree_gist } from '@electric-sql/pglite/contrib/btree_gist';
import { moddatetime } from '@electric-sql/pglite/contrib/moddatetime';
import { cube } from '@electric-sql/pglite/contrib/cube';
import { earthdistance } from '@electric-sql/pglite/contrib/earthdistance';
import { tablefunc } from '@electric-sql/pglite/contrib/tablefunc';
import { intarray } from '@electric-sql/pglite/contrib/intarray';
import { seg } from '@electric-sql/pglite/contrib/seg';
import { isn } from '@electric-sql/pglite/contrib/isn';
import { lo } from '@electric-sql/pglite/contrib/lo';
import { vector } from '@electric-sql/pglite-pgvector';

// Extensions Supabase offers that agents commonly use. They load only when a
// migration creates them.
const EXTENSIONS = { citext, pgcrypto, uuid_ossp, pg_trgm, hstore, ltree, unaccent, fuzzystrmatch, btree_gin, btree_gist, moddatetime, cube, earthdistance, tablefunc, intarray, seg, isn, lo, vector };
export const newEngine = () => new PGlite({ extensions: EXTENSIONS });
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const SHIM = readFileSync(join(here, 'shim.sql'), 'utf8');

// Fixed identities used by every gauntlet run.
// Sign-in tokens carry the user's email; policies often read auth.jwt() ->> 'email'.
export const EMAILS = {
  '00000000-0000-4000-8000-00000000000a': 'alice@example.test',
  '00000000-0000-4000-8000-00000000000b': 'bob@example.test',
  '00000000-0000-4000-8000-00000000000c': 'carol@example.test',
  '00000000-0000-4000-8000-00000000005f': 'sam-staff@example.test',
};

export const IDS = {
  A: '00000000-0000-4000-8000-00000000000a',
  B: '00000000-0000-4000-8000-00000000000b',
  C: '00000000-0000-4000-8000-00000000000c', // a brand-new user, for signup checks
  S: '00000000-0000-4000-8000-00000000005f', // a staff member, made staff the way the server would
  ORG_A: '00000000-0000-4000-8000-0000000000a1',
  ORG_B: '00000000-0000-4000-8000-0000000000b1',
};

// Extensions Supabase has installed (or that the shim provides) are no-ops
// here, like re-running `create extension if not exists` on Supabase.
// Already installed by the shim (as on Supabase), or Supabase-internal ones the
// local engine doesn't have and access control doesn't depend on.
const PROVIDED_EXTENSIONS = new Set(['uuid-ossp', 'pgcrypto', 'pg_graphql', 'pg_stat_statements', 'supabase_vault', 'pgjwt', 'pg_net', 'pg_cron', 'pgsodium', 'http', 'wrappers', 'pg_jsonschema', 'index_advisor', 'hypopg', 'plpgsql']);
export function neutralizeExtensions(sql) {
  // create / drop / alter / comment on an extension the shim already provides.
  return sql.replace(/(?:create|drop|alter)\s+extension\s+(?:if\s+(?:not\s+)?exists\s+)?("?)([\w-]+)\1[^;]*;|comment\s+on\s+extension\s+("?)([\w-]+)\3[^;]*;/gi,
    (m, _q, name, _q2, name2) => (PROVIDED_EXTENSIONS.has(String(name || name2).toLowerCase()) ? `-- provided by shim: ${m.replace(/\n/g, ' ')}` : m));
}

export function fillPlaceholders(sql) {
  return sql.replace(/\{\{(A|B|ORG_A|ORG_B)\}\}/g, (_, k) => IDS[k]);
}

/**
 * Build a fresh database.
 * @param {object} p
 * @param {string[]} p.migrations  SQL applied before fixtures (the app as it is)
 * @param {string}   [p.seed]      fixture SQL with {{A}} {{B}} {{ORG_A}} {{ORG_B}} placeholders
 * @param {string[]} [p.after]     SQL applied after fixtures (the change being verified)
 */
export async function buildDb({ migrations = [], seed = '', after = [], fresh = process.env.VC_FRESH_DB === '1' }) {
  if (!fresh) {
    try {
      return await buildWarm({ migrations, seed, after });
    } catch {
      // Something in the app can't run inside a transaction, or the SQL is
      // simply wrong: redo it on a fresh engine, whose result (or error) stands.
    }
  }
  return buildFresh({ migrations, seed, after });
}

// Private betas: a signup trigger that only admits emails on a list
// (allowlist_entries where email = new.email and status = 'approved'). The
// test users are real beta users of the app, so their emails go on that list
// first, with the conditions the trigger checks.
async function admitTestEmails(db) {
  const fns = (await db.query(`select p.prosrc as src from pg_trigger t join pg_proc p on p.oid = t.tgfoid
    where t.tgrelid = 'auth.users'::regclass and not t.tgisinternal and p.prosrc ~* 'raise' and p.prosrc ~* 'new\\.email'`).catch(() => ({ rows: [] }))).rows;
  for (const { src } of fns) {
    const from = src.match(/\bfrom\s+(?:public\.)?"?(\w+)"?(?:\s+(?:as\s+)?(?!where\b)(\w+))?\s+where\b([\s\S]*?)(?:\)\s*then|;|\)\s*\)|$)/i);
    if (!from) continue;
    const [, table, , cond] = from;
    const emailCol = cond.match(/(?:\w+\.)?(\w+)\s*=\s*(?:lower\s*\(\s*)?(?:trim\s*\(\s*)?(?:lower\s*\(\s*)?new\.email/i)?.[1]
      || cond.match(/(?:lower|trim)?\s*\(?\s*new\.email\s*\)?\s*\)?\s*=\s*(?:lower\s*\(\s*)?(?:\w+\.)?(\w+)/i)?.[1];
    if (!emailCol) continue;
    const fixed = [...cond.matchAll(/(?:\w+\.)?(\w+)\s*=\s*('(?:[^']|'')*'|true|false)/gi)].filter(m => m[1] !== emailCol);
    // Other required text columns (email_original next to email_normalized)
    // get the same address.
    const extra = (await db.query(`select column_name as c from information_schema.columns where table_schema = 'public' and table_name = $1
      and is_nullable = 'NO' and column_default is null and data_type in ('text', 'character varying', 'citext')`, [table]).catch(() => ({ rows: [] }))).rows
      .map(r => r.c).filter(c => c !== emailCol && !fixed.some(m => m[1] === c));
    const cols = [emailCol, ...fixed.map(m => m[1]), ...extra];
    for (const email of Object.values(EMAILS)) {
      const vals = [`'${email}'`, ...fixed.map(m => m[2]), ...extra.map(() => `'${email}'`)];
      await db.exec(`insert into public."${table}" (${cols.map(c => `"${c}"`).join(', ')}) values (${vals.join(', ')}) on conflict do nothing`).catch(() => {});
    }
  }
}

// Supabase applies each migration file in its own transaction, so a file can
// add an enum value and a later file can use it. Split on the file markers
// loadMigrations writes and apply the pieces one at a time.
const splitFiles = sql => String(sql).split(/\n(?=-- file: )/).filter(p => p.trim());
async function load(db, { migrations, seed, after }) {
  for (const m of migrations) for (const part of splitFiles(m)) await db.exec(neutralizeExtensions(part));
  await admitTestEmails(db);
  // Create the two test users one at a time. A signup trigger that writes a
  // unique column (a pseudo, a handle) with the same value for everyone would
  // make the second insert collide; inserting separately means the first user
  // still lands, and if the second collides we retry with a distinct email so
  // the trigger derives a different value, rather than failing the whole build.
  for (const [ph, email] of [['{{A}}', 'alice@example.test'], ['{{B}}', 'bob@example.test']]) {
    try {
      await db.exec(fillPlaceholders(`insert into auth.users (id, email) values ('${ph}', '${email}');`));
    } catch (e) {
      if (!/duplicate key|unique constraint/i.test(String(e.message))) throw e;
      const alt = email.replace('@', `+${ph.replace(/[^a-z0-9]/gi, '')}@`);
      await db.exec(fillPlaceholders(`insert into auth.users (id, email) values ('${ph}', '${alt}');`));
    }
  }
  if (seed) await db.exec(fillPlaceholders(seed));
  for (const m of after) for (const part of splitFiles(m)) await db.exec(neutralizeExtensions(part));
}

async function buildFresh(parts) {
  const db = newEngine();
  await db.exec(SHIM);
  await load(db, parts);
  return db;
}

// Warm path: starting the engine is most of a check's time (about 2 of 2.5
// seconds), so one engine with the shim loaded is kept for the life of the
// process. Each check runs inside one transaction that is always rolled back,
// which leaves the engine exactly as it was; DDL is transactional in Postgres.
// Checks take turns. If a migration ends the transaction itself (its own
// commit or rollback), the engine is thrown away and the check redone fresh.
let warmEngine = null;
let warmTurn = Promise.resolve();

async function engine() {
  if (!warmEngine) {
    warmEngine = (async () => { const e = newEngine(); await e.exec(SHIM); return e; })();
  }
  return warmEngine;
}

// Start the engine ahead of the first check (the MCP server does this at launch).
export function prewarm() { return engine().then(() => true, () => false); }

export async function discardEngine() {
  const e = warmEngine;
  warmEngine = null;
  try { await (await e)?.close(); } catch { /* already gone */ }
}

async function buildWarm(parts) {
  let release;
  const myTurn = new Promise(r => { release = r; });
  const prev = warmTurn;
  warmTurn = prev.then(() => myTurn);
  await prev;
  let e;
  try {
    e = await engine();
    await e.exec(`begin; select set_config('vc.in_check', 'yes', true);`);
    await load(e, parts);
    const still = (await e.query(`select current_setting('vc.in_check', true) as v`)).rows[0]?.v;
    if (still !== 'yes') throw new Error('migration ended the transaction');
  } catch (err) {
    // Rare (bad SQL, or a migration that commits on its own): drop the engine
    // rather than guess what state it's in. The next check starts a new one.
    await discardEngine();
    release();
    throw err;
  }
  let closed = false;
  return {
    nested: true,
    query: (...a) => e.query(...a),
    exec: (...a) => e.exec(...a),
    async close() {
      if (closed) return;
      closed = true;
      try { await e.exec('rollback'); } catch { await discardEngine(); }
      release();
    },
  };
}

/**
 * Run one statement as an API caller, inside a transaction that is always
 * rolled back, so no check can affect another.
 * actor: { role: 'anon' | 'authenticated', sub?: uuid, userMeta?: object }
 */
// setup: optional SQL run as the database owner first, inside the same
// savepoint (a precondition only the server could create, e.g. B being an
// ordinary member of A's team); it is rolled back with the attack.
// verify: a count query run with full rights before and after the attack; the
// attack's effect is the difference (an insert the app's trigger rewrote to the
// attacker's own account didn't land where the attacker aimed it).
export async function runAs(db, actor, sql, params = [], setup = null, verify = null) {
  const claims = actor.role === 'anon'
    ? { role: 'anon' }
    : { role: 'authenticated', aud: 'authenticated', sub: actor.sub, email: EMAILS[actor.sub], aal: 'aal1', amr: [{ method: 'password', timestamp: 1700000000 }], session_id: '00000000-0000-4000-8000-0000000005e5', is_anonymous: false, user_metadata: actor.userMeta || {}, app_metadata: { provider: 'email', providers: ['email'] } };
  // Inside a warm check the whole check is already one transaction, so each
  // attack gets a savepoint instead; rolling back to it also undoes SET LOCAL.
  await db.exec(db.nested ? 'savepoint vc_attack' : 'begin');
  try {
    if (setup) await db.exec(setup);
    const count = async () => Number((await db.query(verify.sql, verify.params || [])).rows[0]?.n ?? 0);
    const before = verify ? await count() : 0;
    await db.query(`select set_config('request.jwt.claims', $1, true)`, [JSON.stringify(claims)]);
    await db.exec(`select set_config('storage.allow_delete_query', 'true', true)`);
    await db.exec(`set local role ${actor.role}`);
    const res = await db.query(sql, params);
    if (verify) {
      await db.exec('reset role');
      return { ok: true, rows: res.rows, affected: (await count()) - before };
    }
    return { ok: true, rows: res.rows, affected: res.affectedRows ?? 0 };
  } catch (e) {
    return { ok: false, error: e.message };
  } finally {
    await db.exec(db.nested ? 'rollback to savepoint vc_attack; release savepoint vc_attack' : 'rollback');
  }
}
