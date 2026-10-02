-- Orders are owner-only, but a summary view (no security_invoker) shows every
-- order to anyone, and a helper view exposes every user's email.
create table public.orders (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references auth.users on delete cascade,
  total_cents int not null
);
alter table public.orders enable row level security;
create policy "own orders" on public.orders for all to authenticated using (customer_id = auth.uid()) with check (customer_id = auth.uid());
create view public.order_history as select o.id, o.customer_id, o.total_cents from public.orders o;
create view public.user_search as select id, email from auth.users;
