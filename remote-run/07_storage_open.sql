-- verified-changes remote gauntlet: 07_storage_open

select vc.reset();

insert into storage.buckets (id, name, public) values ('uploads', 'uploads', false);
-- Bug: the read policy checks the bucket but not the owner.
create policy "read uploads" on storage.objects for select to authenticated using (bucket_id = 'uploads');
create policy "own insert" on storage.objects for insert to authenticated with check (owner = auth.uid());
create policy "own delete" on storage.objects for delete to authenticated using (owner = auth.uid());


insert into auth.users (id, email) values
  ('00000000-0000-4000-8000-00000000000a', 'alice@example.test'), ('00000000-0000-4000-8000-00000000000b', 'bob@example.test') on conflict (id) do nothing;

insert into storage.objects (bucket_id, name, owner) values ('uploads', 'alice/passport.jpg', '00000000-0000-4000-8000-00000000000a'), ('uploads', 'bob/cv.pdf', '00000000-0000-4000-8000-00000000000b');


select jsonb_agg(jsonb_build_object('id', v.id) || vc.probe(v.role, v.claims::jsonb, v.q, v.judge) order by v.ord) as results
from (values
  (0, 'storage.anon.read', 'anon', '{"role":"anon"}', 'select count(*) as n from storage.objects where owner = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (1, 'storage.cross.read', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from storage.objects where owner = ''00000000-0000-4000-8000-00000000000a''', 'count'),
  (2, 'storage.cross.delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from storage.objects where owner = ''00000000-0000-4000-8000-00000000000a''', 'affected'),
  (3, 'storage.cross.blind_delete', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000b","user_metadata":{},"app_metadata":{}}', 'delete from storage.objects', 'affected'),
  (4, 'storage.legit.read_own', 'authenticated', '{"role":"authenticated","sub":"00000000-0000-4000-8000-00000000000a","user_metadata":{},"app_metadata":{}}', 'select count(*) as n from storage.objects where owner = ''00000000-0000-4000-8000-00000000000a''', 'count')
) as v(ord, id, role, claims, q, judge);