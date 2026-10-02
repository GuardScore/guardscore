create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  total_cents int not null
);
alter table public.invoices enable row level security;
-- Bug: user_metadata is editable by the user, so "admin" is self-granted.
create policy "own or admin" on public.invoices for select to authenticated
  using (user_id = auth.uid() or (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
create policy "own insert" on public.invoices for insert to authenticated with check (user_id = auth.uid());
create policy "own update" on public.invoices for update to authenticated using (user_id = auth.uid());
