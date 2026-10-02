-- verified-changes remote gauntlet: 11_self_admin_roles_table

select vc.reset();

-- A separate roles table. The insert policy only checks the row is "yours",
-- so any user can insert (their id, 'admin').
create type public.app_role as enum ('customer', 'admin');
create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  role public.app_role not null default 'customer',
  unique (user_id, role)
);
alter table public.user_roles enable row level security;
create policy "see own roles" on public.user_roles for select to authenticated using (user_id = auth.uid());
create policy "add own roles" on public.user_roles for insert to authenticated with check (user_id = auth.uid());

create or replace function public.has_role(r public.app_role) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = auth.uid() and role = r);
$$;

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  total_cents int not null
);
alter table public.invoices enable row level security;
create policy "own or admin" on public.invoices for select to authenticated using (user_id = auth.uid() or public.has_role('admin'));


insert into auth.users (id, email) values
  ('00000000-0000-4000-8000-00000000000a', 'alice@example.test'), ('00000000-0000-4000-8000-00000000000b', 'bob@example.test') on conflict (id) do nothing;



select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a"}', false);
insert into public."invoices" ("id", "user_id", "total_cents") values ('00000000-0000-4000-8000-f00000000001', '00000000-0000-4000-8000-00000000000a', 1);
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b"}', false);
insert into public."invoices" ("id", "user_id", "total_cents") values ('00000000-0000-4000-8000-f00000000002', '00000000-0000-4000-8000-00000000000b', 2);
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a"}', false);
insert into public."user_roles" ("id", "user_id") values ('00000000-0000-4000-8000-f00000000003', '00000000-0000-4000-8000-00000000000a');
select set_config('request.jwt.claims', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b"}', false);
insert into public."user_roles" ("id", "user_id") values ('00000000-0000-4000-8000-f00000000004', '00000000-0000-4000-8000-00000000000b');
select set_config('request.jwt.claims', '', false);

select jsonb_agg(jsonb_build_object('id', v.id) || vc.probe(v.role, v.claims::jsonb, v.q, v.judge) order by v.ord) as results
from (values
  (0, 'invoices.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."invoices"', 'count'),
  (1, 'invoices.anon.update', 'anon', '{"role":"anon"}', 'update public."invoices" set "user_id" = "user_id" where true', 'affected'),
  (2, 'invoices.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."invoices" where true', 'affected'),
  (3, 'invoices.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."invoices" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (4, 'invoices.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."invoices" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (5, 'invoices.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."invoices" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (6, 'invoices.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."invoices" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (7, 'invoices.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."invoices" set "total_cents" = (jsonb_populate_record(null::public."invoices", ''{"total_cents":1}''::jsonb))."total_cents"', 'affected'),
  (8, 'invoices.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."invoices"', 'affected'),
  (9, 'invoices.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."invoices" ("user_id", "total_cents") select "user_id", "total_cents" from jsonb_populate_record(null::public."invoices", ''{"user_id":"00000000-0000-4000-8000-00000000000a","total_cents":1}''::jsonb)', 'affected'),
  (10, 'invoices.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."invoices" ("user_id", "total_cents") select "user_id", "total_cents" from jsonb_populate_record(null::public."invoices", ''{"user_id":"00000000-0000-4000-8000-00000000000a","total_cents":1}''::jsonb)', 'affected'),
  (11, 'invoices.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."invoices" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (12, 'user_roles.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."user_roles"', 'count'),
  (13, 'user_roles.anon.update', 'anon', '{"role":"anon"}', 'update public."user_roles" set "user_id" = "user_id" where true', 'affected'),
  (14, 'user_roles.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."user_roles" where true', 'affected'),
  (15, 'user_roles.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."user_roles" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (16, 'user_roles.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."user_roles" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (17, 'user_roles.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."user_roles" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (18, 'user_roles.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."user_roles" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (19, 'user_roles.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."user_roles" set "role" = (jsonb_populate_record(null::public."user_roles", ''{"role":"customer"}''::jsonb))."role"', 'affected'),
  (20, 'user_roles.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."user_roles"', 'affected'),
  (21, 'user_roles.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."user_roles" ("role", "user_id") select "role", "user_id" from jsonb_populate_record(null::public."user_roles", ''{"role":"customer","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (22, 'user_roles.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."user_roles" ("role", "user_id") select "role", "user_id" from jsonb_populate_record(null::public."user_roles", ''{"role":"customer","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (23, 'user_roles.self_grant_admin.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'with u as (update public."user_roles" set "role" = ''admin'' where "user_id" = ''00000000-0000-4000-8000-00000000000b'' returning "role") select count(*) as n from u where "role"::text = ''admin''', 'count'),
  (24, 'user_roles.self_grant_admin.insert', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'with i as (insert into public."user_roles" ("role", "user_id") select "role", "user_id" from jsonb_populate_record(null::public."user_roles", ''{"role":"admin","user_id":"00000000-0000-4000-8000-00000000000b"}''::jsonb) returning "role") select count(*) as n from i where "role"::text = ''admin''', 'count')
) as v(ord, id, role, claims, q, judge);