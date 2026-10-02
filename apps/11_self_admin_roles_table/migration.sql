-- A separate roles table. The insert policy only checks the row is "yours",
-- so any user can insert (their id, 'admin').
create type public.app_role as enum ('customer', 'admin');
create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  role public.app_role not null default 'customer',
  unique (user_id, role)
);
alter table public.user_roles enable row level security;
create policy "see own roles" on public.user_roles for select to authenticated using (user_id = auth.uid());
create policy "add own roles" on public.user_roles for insert to authenticated with check (user_id = auth.uid());

create or replace function public.has_role(r public.app_role) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = auth.uid() and role = r);
$$;

create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  total_cents int not null
);
alter table public.invoices enable row level security;
create policy "own or admin" on public.invoices for select to authenticated using (user_id = auth.uid() or public.has_role('admin'));
