-- Helper function for customers to get their order history
create or replace function public.get_my_orders()
returns table (
  id uuid,
  status text,
  total_amount decimal,
  shipping_address text,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
) as $$
select
  o.id,
  o.status,
  o.total_amount,
  o.shipping_address,
  o.created_at,
  o.updated_at
from public.orders o
join public.customers c on o.customer_id = c.id
where c.user_id = auth.uid()
order by o.created_at desc;
$$ language sql security definer;

-- Helper function to get order details with items
create or replace function public.get_order_details(order_id uuid)
returns table (
  order_id uuid,
  status text,
  total_amount decimal,
  created_at timestamp with time zone,
  product_id uuid,
  product_name text,
  quantity integer,
  unit_price decimal
) as $$
select
  o.id,
  o.status,
  o.total_amount,
  o.created_at,
  oi.product_id,
  p.name,
  oi.quantity,
  oi.unit_price
from public.orders o
join public.order_items oi on o.id = oi.order_id
join public.products p on oi.product_id = p.id
join public.customers c on o.customer_id = c.id
where o.id = order_id
  and c.user_id = auth.uid()
order by oi.created_at;
$$ language sql security definer;

-- Grant execute permissions
grant execute on function public.get_my_orders() to authenticated;
grant execute on function public.get_order_details(uuid) to authenticated;
