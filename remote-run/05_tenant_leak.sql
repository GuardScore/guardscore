-- verified-changes remote gauntlet: 05_tenant_leak

select vc.reset();

create table public.orgs (id uuid primary key, name text not null);
create table public.memberships (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  org_id uuid not null references public.orgs(id)
);
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id),
  name text not null
);
alter table public.orgs enable row level security;
alter table public.memberships enable row level security;
alter table public.projects enable row level security;
create policy "members see org" on public.orgs for select to authenticated
  using (id in (select org_id from public.memberships where user_id = auth.uid()));
create policy "own memberships" on public.memberships for select to authenticated using (user_id = auth.uid());
-- Bug: users can create a membership for themselves in any org.
create policy "join" on public.memberships for insert to authenticated with check (user_id = auth.uid());
-- Bug: "logged in" is treated as "member of this org".
create policy "logged in" on public.projects for all to authenticated using (auth.uid() is not null);


insert into auth.users (id, email) values
  ('00000000-0000-4000-8000-00000000000a', 'alice@example.test'), ('00000000-0000-4000-8000-00000000000b', 'bob@example.test') on conflict (id) do nothing;

insert into public.orgs (id, name) values ('00000000-0000-4000-8000-0000000000a1', 'Acme'), ('00000000-0000-4000-8000-0000000000b1', 'Beta');
insert into public.memberships (user_id, org_id) values ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1'), ('00000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-0000000000b1');
insert into public.projects (org_id, name) values ('00000000-0000-4000-8000-0000000000a1', 'acme roadmap'), ('00000000-0000-4000-8000-0000000000b1', 'beta roadmap');


select jsonb_agg(jsonb_build_object('id', v.id) || vc.probe(v.role, v.claims::jsonb, v.q, v.judge) order by v.ord) as results
from (values
  (0, 'memberships.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."memberships"', 'count'),
  (1, 'memberships.anon.update', 'anon', '{"role":"anon"}', 'update public."memberships" set "id" = "id" where true', 'affected'),
  (2, 'memberships.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."memberships" where true', 'affected'),
  (3, 'memberships.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."memberships" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (4, 'memberships.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."memberships" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (5, 'memberships.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."memberships" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (6, 'memberships.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."memberships" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (7, 'memberships.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."memberships"', 'affected'),
  (8, 'memberships.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."memberships" ("org_id", "user_id") select "org_id", "user_id" from jsonb_populate_record(null::public."memberships", ''{"org_id":"00000000-0000-4000-8000-0000000000a1","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (9, 'memberships.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."memberships" ("org_id", "user_id") select "org_id", "user_id" from jsonb_populate_record(null::public."memberships", ''{"org_id":"00000000-0000-4000-8000-0000000000a1","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (10, 'memberships.self_join_other_tenant', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."memberships" ("org_id", "user_id") select "org_id", "user_id" from jsonb_populate_record(null::public."memberships", ''{"org_id":"00000000-0000-4000-8000-0000000000a1","user_id":"00000000-0000-4000-8000-00000000000b"}''::jsonb)', 'affected'),
  (11, 'memberships.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."memberships" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (12, 'orgs.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."orgs"', 'count'),
  (13, 'orgs.anon.update', 'anon', '{"role":"anon"}', 'update public."orgs" set "id" = "id" where true', 'affected'),
  (14, 'orgs.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."orgs" where true', 'affected'),
  (15, 'projects.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."projects"', 'count'),
  (16, 'projects.anon.update', 'anon', '{"role":"anon"}', 'update public."projects" set "id" = "id" where true', 'affected'),
  (17, 'projects.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."projects" where true', 'affected'),
  (18, 'projects.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."projects" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (19, 'projects.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."projects" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (20, 'projects.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "org_id" = "org_id" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (21, 'projects.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."projects" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (22, 'projects.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "name" = (jsonb_populate_record(null::public."projects", ''{"name":"acme roadmap"}''::jsonb))."name"', 'affected'),
  (23, 'projects.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."projects"', 'affected'),
  (24, 'projects.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."projects" ("name", "org_id") select "name", "org_id" from jsonb_populate_record(null::public."projects", ''{"name":"acme roadmap","org_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (25, 'projects.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."projects" ("name", "org_id") select "name", "org_id" from jsonb_populate_record(null::public."projects", ''{"name":"acme roadmap","org_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (26, 'projects.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."projects" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (27, 'projects.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."projects" ("name", "org_id") select "name", "org_id" from jsonb_populate_record(null::public."projects", ''{"name":"acme roadmap","org_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (28, 'projects.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "org_id" = "org_id" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected')
) as v(ord, id, role, claims, q, judge);