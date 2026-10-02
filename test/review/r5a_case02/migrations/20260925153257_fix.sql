
alter table public."shared_notes" enable row level security;
do $$ declare p record; begin
  for p in select policyname from pg_policies where schemaname = 'public' and tablename = 'shared_notes' and cmd in ('SELECT', 'ALL')
    and (qual ~* '^\(*\s*true\s*\)*$' or (qual ~* 'is not null' and qual !~* 'auth\.uid')) loop
    execute format('drop policy %I on public.%I', p.policyname, 'shared_notes');
  end loop;
end $$;
create or replace function public."get_shared_notes_by_token"(p_token text) returns setof public."shared_notes" language sql stable security definer set search_path = public as $$
  select * from public."shared_notes" where "share_token"::text = p_token;
$$;
grant execute on function public."get_shared_notes_by_token"(text) to anon, authenticated;
