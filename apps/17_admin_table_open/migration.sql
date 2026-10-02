-- Being in admin_users makes you an admin, and the table never enabled RLS,
-- so any user can insert themselves.
create table public.admin_users (user_id uuid primary key references auth.users on delete cascade, created_at timestamptz default now());
create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users, body text not null);
alter table public.notes enable row level security;
create policy "own or admin" on public.notes for select to authenticated using (user_id = auth.uid() or exists (select 1 from public.admin_users a where a.user_id = auth.uid()));
create policy "insert own" on public.notes for insert to authenticated with check (user_id = auth.uid());
create policy "update own" on public.notes for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
