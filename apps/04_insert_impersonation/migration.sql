create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  amount_cents int not null
);
alter table public.orders enable row level security;
create policy "own read" on public.orders for select to authenticated using (user_id = auth.uid());
-- Bug: any logged-in user may insert, with any user_id.
create policy "insert" on public.orders for insert to authenticated with check (true);
create policy "own update" on public.orders for update to authenticated using (user_id = auth.uid());
