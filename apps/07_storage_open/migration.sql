insert into storage.buckets (id, name, public) values ('uploads', 'uploads', false);
-- Bug: the read policy checks the bucket but not the owner.
create policy "read uploads" on storage.objects for select to authenticated using (bucket_id = 'uploads');
create policy "own insert" on storage.objects for insert to authenticated with check (owner = auth.uid());
create policy "own delete" on storage.objects for delete to authenticated using (owner = auth.uid());
