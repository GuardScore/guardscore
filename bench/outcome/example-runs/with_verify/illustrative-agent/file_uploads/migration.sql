insert into storage.buckets (id, name, public, file_size_limit) values ('uploads', 'uploads', false, 10485760);
create policy "read own" on storage.objects for select to authenticated using (bucket_id = 'uploads' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "upload own" on storage.objects for insert to authenticated with check (bucket_id = 'uploads' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "delete own" on storage.objects for delete to authenticated using (bucket_id = 'uploads' and (storage.foldername(name))[1] = auth.uid()::text);
