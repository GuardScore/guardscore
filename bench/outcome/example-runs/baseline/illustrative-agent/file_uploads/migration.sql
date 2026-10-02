insert into storage.buckets (id, name, public) values ('uploads', 'uploads', false);
create policy "read" on storage.objects for select to authenticated using (bucket_id = 'uploads');
create policy "upload" on storage.objects for insert to authenticated with check (bucket_id = 'uploads' and (storage.foldername(name))[1] = auth.uid()::text);
