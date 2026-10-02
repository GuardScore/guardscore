-- Staff policies for products (can modify)
create policy "staff_can_modify_products" on public.products
  for insert with check (auth.jwt() ->> 'role' in ('admin', 'staff'));

create policy "staff_can_update_products" on public.products
  for update using (auth.jwt() ->> 'role' in ('admin', 'staff'));

create policy "staff_can_delete_products" on public.products
  for delete using (auth.jwt() ->> 'role' in ('admin', 'staff'));

-- Staff policies for customers (can read all, but not modify)
create policy "staff_can_read_all_customers" on public.customers
  for select using (auth.jwt() ->> 'role' in ('admin', 'staff'));

-- Staff policies for orders (can read all)
create policy "staff_can_read_all_orders" on public.orders
  for select using (auth.jwt() ->> 'role' in ('admin', 'staff'));

-- Staff can update orders (status, timestamps)
create policy "staff_can_update_orders" on public.orders
  for update using (auth.jwt() ->> 'role' in ('admin', 'staff'))
  with check (auth.jwt() ->> 'role' in ('admin', 'staff'));

-- Staff policies for order_items (can read all)
create policy "staff_can_read_all_order_items" on public.order_items
  for select using (auth.jwt() ->> 'role' in ('admin', 'staff'));

-- Helper function for staff to list all orders with customer info
create or replace function public.staff_list_orders(
  p_status text default null,
  p_limit integer default 50,
  p_offset integer default 0
)
returns table (
  id uuid,
  customer_id uuid,
  customer_name text,
  customer_email text,
  status text,
  total_amount decimal,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
) as $$
select
  o.id,
  o.customer_id,
  c.first_name || ' ' || c.last_name,
  c.email,
  o.status,
  o.total_amount,
  o.created_at,
  o.updated_at
from public.orders o
join public.customers c on o.customer_id = c.id
where (p_status is null or o.status = p_status)
order by o.created_at desc
limit p_limit
offset p_offset;
$$ language sql security definer;

-- Helper function for staff to update order status
create or replace function public.staff_update_order_status(
  p_order_id uuid,
  p_status text
)
returns table (
  id uuid,
  status text,
  updated_at timestamp with time zone
) as $$
update public.orders
set
  status = p_status,
  updated_at = now()
where id = p_order_id
returning id, status, updated_at;
$$ language sql security definer;

-- Helper function for staff to view order details
create or replace function public.staff_get_order(p_order_id uuid)
returns table (
  id uuid,
  customer_id uuid,
  customer_name text,
  customer_email text,
  customer_phone text,
  status text,
  total_amount decimal,
  shipping_address text,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
) as $$
select
  o.id,
  o.customer_id,
  c.first_name || ' ' || c.last_name,
  c.email,
  c.phone,
  o.status,
  o.total_amount,
  o.shipping_address,
  o.created_at,
  o.updated_at
from public.orders o
join public.customers c on o.customer_id = c.id
where o.id = p_order_id;
$$ language sql security definer;

-- Grant permissions to staff
grant execute on function public.staff_list_orders(text, integer, integer) to authenticated;
grant execute on function public.staff_update_order_status(uuid, text) to authenticated;
grant execute on function public.staff_get_order(uuid) to authenticated;
