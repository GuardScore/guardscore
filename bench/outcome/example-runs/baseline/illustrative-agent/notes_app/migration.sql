create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid references auth.users(id), body text);
alter table public.notes enable row level security;
create policy "read" on public.notes for select to authenticated using (true);
create policy "write" on public.notes for insert to authenticated with check (auth.uid() = user_id);
create policy "edit" on public.notes for update to authenticated using (auth.uid() = user_id);
create policy "del" on public.notes for delete to authenticated using (auth.uid() = user_id);
