
create schema if not exists vc;
revoke all on schema vc from public, anon, authenticated;
create or replace function vc.probe(p_role text, p_claims jsonb, p_sql text, p_judge text)
returns jsonb language plpgsql as $fn$
declare n bigint; d text; res jsonb;
begin
  begin
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
revoke all on function vc.probe(text, jsonb, text, text) from public, anon, authenticated;
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
revoke all on function vc.reset() from public, anon, authenticated;

