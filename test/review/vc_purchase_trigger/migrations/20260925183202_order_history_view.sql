-- Create a view for complete order history with product details
-- Security: only includes rows the current user can access via RLS on underlying tables
create view order_history_with_items with (security_invoker = true) as
select
  o.id as order_id,
  o.customer_id,
  o.status,
  o.total_amount,
  o.created_at as order_date,
  o.updated_at as order_updated_at,
  oi.id as item_id,
  oi.product_id,
  p.name as product_name,
  p.description as product_description,
  oi.quantity,
  oi.price_at_purchase,
  (oi.quantity * oi.price_at_purchase) as item_total
from orders o
join order_items oi on o.id = oi.order_id
join products p on oi.product_id = p.id
order by o.created_at desc, o.id, oi.id;

-- Create a function to get a customer's order summary (aggregated)
create or replace function get_customer_order_summary()
returns table (
  order_id uuid,
  status text,
  total_amount decimal,
  item_count bigint,
  order_date timestamp with time zone
) as $$
  select
    o.id,
    o.status,
    o.total_amount,
    count(oi.id),
    o.created_at
  from orders o
  left join order_items oi on o.id = oi.order_id
  where o.customer_id = auth.uid()
  group by o.id, o.status, o.total_amount, o.created_at
  order by o.created_at desc;
$$ language sql security definer;

-- Create a function to get details of a specific order
create or replace function get_order_details(order_id_param uuid)
returns table (
  order_id uuid,
  status text,
  total_amount decimal,
  order_date timestamp with time zone,
  product_name text,
  product_description text,
  quantity integer,
  price_at_purchase decimal,
  item_total decimal
) as $$
  select
    o.id,
    o.status,
    o.total_amount,
    o.created_at,
    p.name,
    p.description,
    oi.quantity,
    oi.price_at_purchase,
    (oi.quantity * oi.price_at_purchase)::decimal
  from orders o
  join order_items oi on o.id = oi.order_id
  join products p on oi.product_id = p.id
  where o.id = order_id_param
    and o.customer_id = auth.uid()
  order by oi.created_at;
$$ language sql security definer;
