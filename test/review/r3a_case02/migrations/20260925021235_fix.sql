
create schema if not exists private;
grant usage on schema private to anon, authenticated;
do $fix$ declare x text; p record; u text; c text; r text; e text;
begin
  -- the tables whose lookups loop back into team_members: team_members itself, and any table whose policies read team_members
  for x in select 'team_members' union select distinct tablename from pg_policies where schemaname = 'public' and tablename <> 'team_members'
      and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) ~* format('(from|join)\s+(public\.)?"?%s"?([^a-z0-9_.]|$)', 'team_members') loop
    e := regexp_replace(x, '([.*+?^${}()|\[\]\\])', '\\\1', 'g');
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'team_members'
      and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) ~* format('(from|join)\s+(public\.)?"?%s"?([^a-z0-9_.]|$)', e)) then continue; end if;
    execute format('create or replace function private.%I() returns setof public.%I language sql stable security definer set search_path = pg_catalog, public as $f$ select * from public.%I $f$', x || '_rows', x, x);
    execute format('revoke all on function private.%I() from public', x || '_rows');
    execute format('grant execute on function private.%I() to anon, authenticated', x || '_rows');
    for p in select * from pg_policies where schemaname = 'public' and tablename = 'team_members'
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

create or replace function public."zz_vc_add_creator_to_team_members"() returns trigger language plpgsql security definer set search_path = public as $trg$
begin
  if auth.uid() is not null and not exists (select 1 from public."team_members" where "user_id" = auth.uid() and "team_id" = new."id") then
    insert into public."team_members" ("user_id", "team_id", "role") values (auth.uid(), new."id", 'admin');
  end if;
  return new;
end $trg$;
drop trigger if exists "zz_vc_add_creator_to_team_members" on public."teams";
create trigger "zz_vc_add_creator_to_team_members" after insert on public."teams" for each row execute function public."zz_vc_add_creator_to_team_members"();
