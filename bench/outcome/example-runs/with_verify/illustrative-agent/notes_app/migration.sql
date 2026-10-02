create extension if not exists "uuid-ossp";
create table public.notes (id uuid primary key default uuid_generate_v4(), user_id uuid references auth.users(id) default auth.uid(), body text);
alter table public.notes enable row level security;
create policy "own" on public.notes for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
