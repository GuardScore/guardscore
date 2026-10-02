// Runs the gauntlet against a real Supabase database.
//
// The attack list is planned locally (same code, same fixtures), then emitted as
// one SQL bundle per app: reset the scratch database, load the app, and run every
// attack through vc.probe, which executes it as the right role inside a
// subtransaction that is always rolled back. The returned JSON is judged by the
// same code as the local run, then compared attack by attack.
//
//   node src/remote.js setup                      -> SQL that installs vc.probe (once)
//   node src/remote.js plan  <app-dir> <out-dir>  -> <out-dir>/<app>.sql and <app>.plan.json
//   node src/remote.js score <app-dir> <out-dir> <results.json>
//
// Only run against a dedicated, empty project: the bundle drops every table in public.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { loadApp } from './verify.js';
import { buildDb, runAs, fillPlaceholders, IDS, EMAILS } from './db.js';
import { introspect } from './introspect.js';
import { autoFixtures } from './fixtures.js';
import { gauntlet, judgeResult, applyDependencies, summarize } from './gauntlet.js';

const lit = s => `'${String(s).replace(/'/g, "''")}'`;

export const SETUP_SQL = `
create schema if not exists vc;
revoke all on schema vc from public, anon, authenticated;
drop function if exists vc.probe(text, jsonb, text, text);
create or replace function vc.probe(p_role text, p_claims jsonb, p_sql text, p_judge text, p_setup text default null)
returns jsonb language plpgsql as $fn$
declare n bigint; d text; res jsonb;
begin
  begin
    if p_setup is not null then execute p_setup; end if;
    perform set_config('request.jwt.claims', p_claims::text, true);
    perform set_config('storage.allow_delete_query', 'true', true);
    execute format('set local role %I', p_role);
    if p_judge = 'count' then
      execute p_sql into n;
    else
      execute p_sql;
      get diagnostics n = row_count;
    end if;
    raise exception using message = 'vc_rollback', detail = n::text;
  exception when others then
    get stacked diagnostics d = pg_exception_detail;
    if sqlerrm = 'vc_rollback' then
      res := jsonb_build_object('ok', true, 'n', d::bigint);
    else
      res := jsonb_build_object('ok', false, 'error', sqlerrm);
    end if;
  end;
  return res;
end $fn$;
alter function vc.probe(text, jsonb, text, text, text) set search_path = pg_catalog, public;
revoke all on function vc.probe(text, jsonb, text, text, text) from public, anon, authenticated;
create or replace function vc.reset() returns void language plpgsql as $reset$
declare r record;
begin
  -- Everything an app can leave behind: signup triggers on auth.users, views,
  -- tables, standalone sequences, functions and types in public (never objects
  -- that belong to an installed extension).
  for r in select tgname from pg_trigger where tgrelid = 'auth.users'::regclass and not tgisinternal loop
    execute format('drop trigger if exists %I on auth.users', r.tgname);
  end loop;
  for r in select viewname from pg_views where schemaname = 'public' loop
    execute format('drop view if exists public.%I cascade', r.viewname);
  end loop;
  for r in select tablename from pg_tables where schemaname = 'public' loop
    execute format('drop table if exists public.%I cascade', r.tablename);
  end loop;
  for r in select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
           where n.nspname = 'public' and c.relkind = 'S'
             and not exists (select 1 from pg_depend d where d.objid = c.oid and d.deptype = 'e') loop
    execute format('drop sequence if exists public.%I cascade', r.relname);
  end loop;
  for r in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'public' and p.prokind in ('f', 'p')
             and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e') loop
    execute format('drop routine if exists %s cascade', r.sig);
  end loop;
  for r in select t.typname from pg_type t join pg_namespace n on n.oid = t.typnamespace
           where n.nspname = 'public' and (t.typtype in ('e', 'd')
                 or (t.typtype = 'c' and (select relkind from pg_class where oid = t.typrelid) = 'c'))
             and not exists (select 1 from pg_depend d where d.objid = t.oid and d.deptype = 'e') loop
    execute format('drop type if exists public.%I cascade', r.typname);
  end loop;
  for r in select policyname from pg_policies where schemaname = 'storage' and tablename = 'objects' loop
    execute format('drop policy %I on storage.objects', r.policyname);
  end loop;
  perform set_config('storage.allow_delete_query', 'true', true);
  delete from storage.objects;
  delete from storage.buckets;
  delete from auth.users where id in ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000b');
end $reset$;
alter function vc.reset() set search_path = pg_catalog, public;
revoke all on function vc.reset() from public, anon, authenticated;
`;

function claimsFor(actor) {
  return actor.role === 'anon'
    ? { role: 'anon' }
    : { role: 'authenticated', aud: 'authenticated', sub: actor.sub, email: EMAILS[actor.sub], aal: 'aal1', amr: [{ method: 'password', timestamp: 1700000000 }], session_id: '00000000-0000-4000-8000-0000000005e5', is_anonymous: false, user_metadata: actor.userMeta || {}, app_metadata: { provider: 'email', providers: ['email'] } };
}

function inlineParams(sql, params = []) {
  return params.reduce((s, p, i) => s.split(`$${i + 1}`).join(lit(p)), sql);
}

export async function plan(app) {
  const db = await buildDb({ migrations: [app.migration], seed: app.seed });
  try {
    const fixtures = await autoFixtures(db, app.manifest);
    const schema = await introspect(db, app.manifest);
    for (const t of schema) {
      if (fixtures.privilegeProbes?.[t.name]) t.privilegeProbe = fixtures.privilegeProbes[t.name];
      if (fixtures.shareTables?.includes(t.name)) t.shareTable = true;
    }
    const specs = [];
    const exec = async spec => {
      specs.push(spec);
      return judgeResult(spec, await runAs(db, spec.actor, spec.sql, spec.params || [], spec.setup || null));
    };
    const local = await gauntlet(db, schema, exec);
    return { schema, specs, local, fixtureSql: fixtures.sql, skipped: fixtures.skipped };
  } finally {
    await db.close();
  }
}

export function bundleSql(app, specs, fixtureSql = '') {
  const reset = `select vc.reset();`;
  const users = fillPlaceholders(`insert into auth.users (id, email) values
  ('{{A}}', 'alice@example.test'), ('{{B}}', 'bob@example.test') on conflict (id) do nothing;`);
  const rows = specs.map((s, i) =>
    `(${i}, ${lit(s.id)}, ${lit(s.actor.role)}, ${lit(JSON.stringify(claimsFor(s.actor)))}, ${lit(inlineParams(s.sql, s.params))}, ${lit(s.judge)}, ${s.setup ? lit(s.setup) : 'null::text'})`);
  const probes = `select jsonb_agg(jsonb_build_object('id', v.id) || vc.probe(v.role, v.claims::jsonb, v.q, v.judge, v.setup) order by v.ord) as results
from (values
  ${rows.join(',\n  ')}
) as v(ord, id, role, claims, q, judge, setup);`;
  return [`-- verified-changes remote gauntlet: ${app.name}`, reset, app.migration, users, fillPlaceholders(app.seed), fixtureSql, probes].join('\n\n');
}

export function score(planned, remoteResults) {
  const byId = new Map(remoteResults.map(r => [r.id, r]));
  const judged = planned.specs.map(s => {
    const r = byId.get(s.id);
    return r ? judgeResult(s, r) : judgeResult(s, { ok: false, error: 'missing from remote results' });
  });
  const remote = applyDependencies(judged);
  // Coverage gaps are decided locally (no rows to test); carry them over as-is.
  for (const r of planned.local.filter(x => x.kind === 'coverage')) remote.push(r);
  const localById = new Map(planned.local.map(r => [r.id, r.status]));
  const ids = new Set([...remote.map(r => r.id), ...planned.local.map(r => r.id)]);
  const diffs = [...ids].map(id => ({
    id,
    local: localById.get(id) || '(not run)',
    supabase: remote.find(r => r.id === id)?.status || '(not run)',
  })).filter(d => d.local !== d.supabase);
  const opts = { skipped: planned.skipped || [] };
  return { remote, summary: summarize(remote, opts), localSummary: summarize(planned.local, opts), diffs };
}

const [cmd, appDir, outDir, resultsFile] = process.argv.slice(2);
if (import.meta.url === `file://${process.argv[1]}`) {
  if (cmd === 'setup') {
    console.log(SETUP_SQL);
  } else if (cmd === 'plan' && appDir && outDir) {
    const app = loadApp(appDir);
    const p = await plan(app);
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, `${app.name}.sql`), bundleSql(app, p.specs, p.fixtureSql));
    writeFileSync(join(outDir, `${app.name}.plan.json`), JSON.stringify({ specs: p.specs, local: p.local, skipped: p.skipped }, null, 2));
    console.log(`${app.name}: ${p.specs.length} attacks planned -> ${join(outDir, app.name + '.sql')}`);
  } else if (cmd === 'score' && appDir && outDir && resultsFile) {
    const app = loadApp(appDir);
    const planned = JSON.parse(readFileSync(join(outDir, `${app.name}.plan.json`), 'utf8'));
    const remoteResults = JSON.parse(readFileSync(resultsFile, 'utf8'));
    const s = score(planned, remoteResults);
    writeFileSync(join(outDir, `${app.name}.score.json`), JSON.stringify(s, null, 2));
    console.log(`${app.name}: local ${s.localSummary.verdict} (${s.localSummary.guardScore}) | Supabase ${s.summary.verdict} (${s.summary.guardScore}) | ${s.diffs.length} differences`);
    for (const d of s.diffs) {
      const r = s.remote.find(x => x.id === d.id);
      console.log(`  ${d.id}: local ${d.local}, Supabase ${d.supabase}${r?.proof.observed.error ? ' (' + r.proof.observed.error + ')' : ''}`);
    }
  } else {
    console.log('usage: setup | plan <app-dir> <out-dir> | score <app-dir> <out-dir> <results.json>');
  }
}
