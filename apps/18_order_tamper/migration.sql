-- Customers may edit their own orders (to fix the shipping address), staff
-- manage status. Nothing stops a customer marking their own order paid.
create table public.staff (user_id uuid primary key references auth.users on delete cascade);
alter table public.staff enable row level security;
create policy "staff see themselves" on public.staff for select to authenticated using (user_id = auth.uid());
create or replace function public.is_staff() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.staff where user_id = auth.uid());
$$;
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references auth.users on delete cascade,
  shipping_address text,
  total_cents int not null,
  status text not null default 'pending' check (status in ('pending', 'paid', 'shipped', 'cancelled'))
);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for select to authenticated using (customer_id = auth.uid() or public.is_staff());
create policy "create own orders" on public.orders for insert to authenticated with check (customer_id = auth.uid());
create policy "edit own orders" on public.orders for update to authenticated using (customer_id = auth.uid()) with check (customer_id = auth.uid());
create policy "staff manage orders" on public.orders for update to authenticated using (public.is_staff()) with check (public.is_staff());
