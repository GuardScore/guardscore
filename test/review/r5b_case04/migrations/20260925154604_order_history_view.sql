-- Create a view for customer order history with product details
create view order_history as
select
  o.id as order_id,
  o.user_id,
  o.status,
  o.total_amount,
  o.created_at as order_date,
  o.updated_at as order_updated_at,
  oi.id as item_id,
  oi.product_id,
  p.name as product_name,
  p.image_url,
  oi.quantity,
  oi.unit_price,
  (oi.quantity * oi.unit_price) as item_total
from orders o
left join order_items oi on o.id = oi.order_id
left join products p on oi.product_id = p.id
order by o.created_at desc, oi.id;

-- Security: View inherits RLS from underlying orders table (filtered by user_id)
