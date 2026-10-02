-- Create a view for customers to see their order history with product details
-- security_invoker = true ensures RLS policies are respected
create view order_history with (security_invoker = true) as
  select
    o.id as order_id,
    o.status,
    o.total_amount,
    o.created_at as order_date,
    o.updated_at as last_updated,
    o.shipping_address,
    oi.id as item_id,
    oi.product_id,
    p.name as product_name,
    p.sku,
    oi.quantity,
    oi.unit_price,
    (oi.quantity * oi.unit_price) as item_total,
    c.user_id
  from orders o
  join customers c on o.customer_id = c.id
  join order_items oi on o.id = oi.order_id
  join products p on oi.product_id = p.id;

-- Create an index on the underlying table to speed up order history queries
create index if not exists idx_orders_customer_created on orders(customer_id, created_at desc);
