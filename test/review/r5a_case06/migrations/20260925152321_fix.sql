
create schema if not exists private;
grant usage on schema private to anon, authenticated;
do $fix$ declare x text; p record; u text; c text; r text; e text;
begin
  -- the tables whose lookups loop back into profiles: profiles itself, and any table whose policies read profiles
  for x in select 'profiles' union select distinct tablename from pg_policies where schemaname = 'public' and tablename <> 'profiles'
      and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) ~* format('(from|join)\s+(public\.)?"?%s"?([^a-z0-9_.]|$)', 'profiles') loop
    e := regexp_replace(x, '([.*+?^${}()|\[\]\\])', '\\\1', 'g');
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'profiles'
      and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) ~* format('(from|join)\s+(public\.)?"?%s"?([^a-z0-9_.]|$)', e)) then continue; end if;
    execute format('create or replace function private.%I() returns setof public.%I language sql stable security definer set search_path = pg_catalog, public as $f$ select * from public.%I $f$', x || '_rows', x, x);
    execute format('revoke all on function private.%I() from public', x || '_rows');
    execute format('grant execute on function private.%I() to anon, authenticated', x || '_rows');
    for p in select * from pg_policies where schemaname = 'public' and tablename = 'profiles'
      and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) ~* format('(from|join)\s+(public\.)?"?%s"?([^a-z0-9_.]|$)', e) loop
      u := p.qual; c := p.with_check;
      -- no alias: keep the table name as the alias so column references still resolve
      u := regexp_replace(u, format('(from|join)\s+(public\.)?"?%s"?(?=\s+(where|join|left|right|inner|full|cross|on|group|order|limit|offset|union|except|intersect)\M|\s*\)|\s*$)', e), format('\1 private.%I() %I', x || '_rows', x), 'gi');
      c := regexp_replace(c, format('(from|join)\s+(public\.)?"?%s"?(?=\s+(where|join|left|right|inner|full|cross|on|group|order|limit|offset|union|except|intersect)\M|\s*\)|\s*$)', e), format('\1 private.%I() %I', x || '_rows', x), 'gi');
      u := regexp_replace(u, format('(from|join)\s+(public\.)?"?%s"?(?=\s+[a-z_"])', e), format('\1 private.%I()', x || '_rows'), 'gi');
      c := regexp_replace(c, format('(from|join)\s+(public\.)?"?%s"?(?=\s+[a-z_"])', e), format('\1 private.%I()', x || '_rows'), 'gi');
      select string_agg(quote_ident(y), ', ') into r from unnest(p.roles) y;
      execute format('drop policy %I on public.%I', p.policyname, p.tablename);
      execute format('create policy %I on public.%I as %s for %s to %s', p.policyname, p.tablename, p.permissive, p.cmd, r)
        || coalesce(' using (' || u || ')', '') || coalesce(' with check (' || c || ')', '');
    end loop;
  end loop;
end $fix$;

create or replace function public."lock_profiles_is_admin"() returns trigger language plpgsql as $lock$
begin
  -- pg_trigger_depth() = 1: the client's own statement; the app's triggers (recomputing a total) still work
  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 then
    if tg_op = 'INSERT' then
      new."is_admin" := 'false';
    elsif new."is_admin" is distinct from old."is_admin" then
      raise exception 'permission denied: only the server can change is_admin';
    end if;
  end if;
  return new;
end $lock$;
drop trigger if exists "lock_profiles_is_admin" on public."profiles";
create trigger "lock_profiles_is_admin" before insert or update on public."profiles" for each row execute function public."lock_profiles_is_admin"();
