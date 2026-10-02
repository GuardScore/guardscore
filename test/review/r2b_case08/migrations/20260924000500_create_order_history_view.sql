-- Create view for customer order history with item counts and totals
create or replace view order_history as
select
  o.id,
  o.status,
  o.total_amount,
  o.created_at,
  o.updated_at,
  count(oi.id) as item_count,
  string_agg(p.name, ', ') as product_names,
  o.user_id
from orders o
left join order_items oi on o.id = oi.order_id
left join products p on oi.product_id = p.id
group by o.id, o.status, o.total_amount, o.created_at, o.updated_at, o.user_id;

-- Grant permissions (RLS on underlying orders table will apply)
grant select on order_history to authenticated, anon;
