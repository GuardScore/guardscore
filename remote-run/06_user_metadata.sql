-- verified-changes remote gauntlet: 06_user_metadata

select vc.reset();

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  total_cents int not null
);
alter table public.invoices enable row level security;
-- Bug: user_metadata is editable by the user, so "admin" is self-granted.
create policy "own or admin" on public.invoices for select to authenticated
  using (user_id = auth.uid() or (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
create policy "own insert" on public.invoices for insert to authenticated with check (user_id = auth.uid());
create policy "own update" on public.invoices for update to authenticated using (user_id = auth.uid());


insert into auth.users (id, email) values
  ('00000000-0000-4000-8000-00000000000a', 'alice@example.test'), ('00000000-0000-4000-8000-00000000000b', 'bob@example.test') on conflict (id) do nothing;

insert into public.invoices (user_id, total_cents) values ('00000000-0000-4000-8000-00000000000a', 12000), ('00000000-0000-4000-8000-00000000000b', 3000);


select jsonb_agg(jsonb_build_object('id', v.id) || vc.probe(v.role, v.claims::jsonb, v.q, v.judge) order by v.ord) as results
from (values
  (0, 'invoices.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."invoices"', 'count'),
  (1, 'invoices.anon.update', 'anon', '{"role":"anon"}', 'update public."invoices" set "id" = "id" where true', 'affected'),
  (2, 'invoices.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."invoices" where true', 'affected'),
  (3, 'invoices.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."invoices" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (4, 'invoices.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."invoices" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (5, 'invoices.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."invoices" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (6, 'invoices.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."invoices" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (7, 'invoices.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."invoices" set "total_cents" = (jsonb_populate_record(null::public."invoices", ''{"total_cents":12000}''::jsonb))."total_cents"', 'affected'),
  (8, 'invoices.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."invoices"', 'affected'),
  (9, 'invoices.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."invoices" ("user_id", "total_cents") select "user_id", "total_cents" from jsonb_populate_record(null::public."invoices", ''{"user_id":"00000000-0000-4000-8000-00000000000a","total_cents":12000}''::jsonb)', 'affected'),
  (10, 'invoices.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."invoices" ("user_id", "total_cents") select "user_id", "total_cents" from jsonb_populate_record(null::public."invoices", ''{"user_id":"00000000-0000-4000-8000-00000000000a","total_cents":12000}''::jsonb)', 'affected'),
  (11, 'invoices.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."invoices" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (12, 'invoices.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."invoices" ("user_id", "total_cents") select "user_id", "total_cents" from jsonb_populate_record(null::public."invoices", ''{"user_id":"00000000-0000-4000-8000-00000000000a","total_cents":12000}''::jsonb)', 'affected'),
  (13, 'invoices.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."invoices" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected')
) as v(ord, id, role, claims, q, judge);