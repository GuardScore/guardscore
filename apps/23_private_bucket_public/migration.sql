-- Invoices uploaded by users, in a bucket someone made public.
insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true);
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "owners read their invoices" on storage.objects for select to authenticated using (bucket_id = 'invoices' and owner = auth.uid());
create policy "owners upload invoices" on storage.objects for insert to authenticated with check (bucket_id = 'invoices' and owner = auth.uid());
