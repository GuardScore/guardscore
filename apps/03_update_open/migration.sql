create table public.profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  display_name text,
  plan text default 'free'
);
alter table public.profiles enable row level security;
create policy "own read" on public.profiles for select to authenticated using (user_id = auth.uid());
create policy "own insert" on public.profiles for insert to authenticated with check (user_id = auth.uid());
-- Bug: the update policy forgot the ownership check.
create policy "update" on public.profiles for update to authenticated using (true);
