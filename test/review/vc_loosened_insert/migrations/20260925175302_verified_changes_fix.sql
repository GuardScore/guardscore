-- Fixes from Verified Changes (2026-09-25).
-- Each block was applied to a private copy of this database and re-checked: the attacks it
-- targets are blocked and the app's real users can still do what they did before.

-- invoice_items: Any signed-in user can change or delete rows that belong to nobody in particular (a product catalog, settings), for example set every price to 0.
-- PROVEN: applied to the private copy and re-checked: 2 finding(s) now blocked, real users on "invoice_items" still work, nothing new leaks
alter table public."invoice_items" enable row level security;
do $fix$ declare p record; r text; begin
  for p in select * from pg_policies where schemaname = 'public' and tablename = 'invoice_items' and cmd in ('INSERT', 'UPDATE', 'DELETE', 'ALL')
    and (coalesce(qual, '') || ' ' || coalesce(with_check, '')) !~* '(admin|staff|manager|moderator|is_[a-z_]+\()' loop
    execute format('drop policy %I on public.%I', p.policyname, p.tablename);
    if p.cmd = 'ALL' then
      select string_agg(quote_ident(y), ', ') into r from unnest(p.roles) y;
      execute format('create policy %I on public.%I for select to %s using (%s)', p.policyname, p.tablename, r, coalesce(p.qual, 'true'));
    end if;
  end loop;
  if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'invoice_items' and cmd in ('SELECT', 'ALL')) then
    execute 'create policy "invoice_items_read" on public."invoice_items" for select to authenticated using (true)';
  end if;
end $fix$;
