-- verified-changes remote gauntlet: 08_secure

select vc.reset();

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  body text not null
);
alter table public.notes enable row level security;
create policy "notes_select_own" on public.notes for select to authenticated using (user_id = auth.uid());
create policy "notes_insert_own" on public.notes for insert to authenticated with check (user_id = auth.uid());
create policy "notes_update_own" on public.notes for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "notes_delete_own" on public.notes for delete to authenticated using (user_id = auth.uid());

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
create policy "members only" on public.projects for all to authenticated
  using (org_id in (select org_id from public.memberships where user_id = auth.uid()))
  with check (org_id in (select org_id from public.memberships where user_id = auth.uid()));

insert into storage.buckets (id, name, public) values ('uploads', 'uploads', false);
create policy "owner only" on storage.objects for all to authenticated using (owner = auth.uid()) with check (owner = auth.uid());


insert into auth.users (id, email) values
  ('00000000-0000-4000-8000-00000000000a', 'alice@example.test'), ('00000000-0000-4000-8000-00000000000b', 'bob@example.test') on conflict (id) do nothing;

insert into public.notes (user_id, body) values ('00000000-0000-4000-8000-00000000000a', 'alice private note'), ('00000000-0000-4000-8000-00000000000b', 'bob private note');
insert into public.orgs (id, name) values ('00000000-0000-4000-8000-0000000000a1', 'Acme'), ('00000000-0000-4000-8000-0000000000b1', 'Beta');
insert into public.memberships (user_id, org_id) values ('00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-0000000000a1'), ('00000000-0000-4000-8000-00000000000b', '00000000-0000-4000-8000-0000000000b1');
insert into public.projects (org_id, name) values ('00000000-0000-4000-8000-0000000000a1', 'acme roadmap'), ('00000000-0000-4000-8000-0000000000b1', 'beta roadmap');
insert into storage.objects (bucket_id, name, owner) values ('uploads', 'alice/passport.jpg', '00000000-0000-4000-8000-00000000000a'), ('uploads', 'bob/cv.pdf', '00000000-0000-4000-8000-00000000000b');


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
  (12, 'notes.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."notes"', 'count'),
  (13, 'notes.anon.update', 'anon', '{"role":"anon"}', 'update public."notes" set "id" = "id" where true', 'affected'),
  (14, 'notes.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."notes" where true', 'affected'),
  (15, 'notes.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (16, 'notes.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (17, 'notes.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."notes" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (18, 'notes.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (19, 'notes.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."notes" set "body" = (jsonb_populate_record(null::public."notes", ''{"body":"alice private note"}''::jsonb))."body"', 'affected'),
  (20, 'notes.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."notes"', 'affected'),
  (21, 'notes.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."notes" ("body", "user_id") select "body", "user_id" from jsonb_populate_record(null::public."notes", ''{"body":"alice private note","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (22, 'notes.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."notes" ("body", "user_id") select "body", "user_id" from jsonb_populate_record(null::public."notes", ''{"body":"alice private note","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (23, 'notes.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (24, 'notes.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."notes" ("body", "user_id") select "body", "user_id" from jsonb_populate_record(null::public."notes", ''{"body":"alice private note","user_id":"00000000-0000-4000-8000-00000000000a"}''::jsonb)', 'affected'),
  (25, 'notes.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."notes" set "user_id" = "user_id" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (26, 'notes.legit.delete_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'delete from public."notes" where "user_id" = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (27, 'orgs.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."orgs"', 'count'),
  (28, 'orgs.anon.update', 'anon', '{"role":"anon"}', 'update public."orgs" set "id" = "id" where true', 'affected'),
  (29, 'orgs.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."orgs" where true', 'affected'),
  (30, 'projects.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from public."projects"', 'count'),
  (31, 'projects.anon.update', 'anon', '{"role":"anon"}', 'update public."projects" set "id" = "id" where true', 'affected'),
  (32, 'projects.anon.delete', 'anon', '{"role":"anon"}', 'delete from public."projects" where true', 'affected'),
  (33, 'projects.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."projects" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (34, 'projects.forged_meta.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{"role":"admin","is_admin":true,"admin":true},"app_metadata":{}}', 'select count(*) as n from public."projects" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (35, 'projects.cross.update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "org_id" = "org_id" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (36, 'projects.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."projects" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (37, 'projects.cross.blind_update', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "name" = (jsonb_populate_record(null::public."projects", ''{"name":"acme roadmap"}''::jsonb))."name"', 'affected'),
  (38, 'projects.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from public."projects"', 'affected'),
  (39, 'projects.cross.insert_as_other', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'insert into public."projects" ("name", "org_id") select "name", "org_id" from jsonb_populate_record(null::public."projects", ''{"name":"acme roadmap","org_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (40, 'projects.anon.insert', 'anon', '{"role":"anon"}', 'insert into public."projects" ("name", "org_id") select "name", "org_id" from jsonb_populate_record(null::public."projects", ''{"name":"acme roadmap","org_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (41, 'projects.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from public."projects" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'count'),
  (42, 'projects.legit.insert_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'insert into public."projects" ("name", "org_id") select "name", "org_id" from jsonb_populate_record(null::public."projects", ''{"name":"acme roadmap","org_id":"00000000-0000-4000-8000-0000000000a1"}''::jsonb)', 'affected'),
  (43, 'projects.legit.update_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'update public."projects" set "org_id" = "org_id" where "org_id" = ''00000000-0000-4000-8000-0000000000a1''', 'affected'),
  (44, 'storage.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from storage.objects where owner = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (45, 'storage.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from storage.objects where owner = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (46, 'storage.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from storage.objects where owner = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (47, 'storage.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from storage.objects', 'affected'),
  (48, 'storage.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from storage.objects where owner = ''00000000-0000-4000-8000-00000000000a''', 'count')
) as v(ord, id, role, claims, q, judge);