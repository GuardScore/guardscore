-- Create view for staff to see all orders with customer info
create or replace view staff_orders as
select
  o.id,
  o.customer_id,
  c.name as customer_name,
  c.email as customer_email,
  o.status,
  o.total_amount,
  o.created_at,
  o.updated_at,
  count(oi.id) as item_count
from orders o
join customers c on o.customer_id = c.id
left join order_items oi on o.id = oi.order_id
group by o.id, o.customer_id, c.name, c.email, o.status, o.total_amount, o.created_at, o.updated_at;

-- Grant permissions (only staff can see)
grant select on staff_orders to authenticated;

-- Create view for staff to see all customers
create or replace view staff_customers as
select
  c.id,
  c.user_id,
  c.name,
  c.email,
  c.phone,
  c.address,
  c.city,
  c.state,
  c.postal_code,
  c.country,
  c.created_at,
  count(distinct o.id) as order_count,
  sum(o.total_amount) as total_spent
from customers c
left join orders o on c.id = o.customer_id
group by c.id, c.user_id, c.name, c.email, c.phone, c.address, c.city, c.state, c.postal_code, c.country, c.created_at;

-- Grant permissions (only staff can see)
grant select on staff_customers to authenticated;

-- Create view for order details with all items
create or replace view staff_order_details as
select
  o.id as order_id,
  c.name as customer_name,
  c.email as customer_email,
  c.phone as customer_phone,
  o.status,
  o.total_amount,
  o.shipping_address,
  o.notes,
  o.created_at,
  o.updated_at,
  json_agg(
    json_build_object(
      'item_id', oi.id,
      'product_id', oi.product_id,
      'product_name', p.name,
      'quantity', oi.quantity,
      'price_at_purchase', oi.price_at_purchase,
      'subtotal', oi.quantity * oi.price_at_purchase
    ) order by oi.created_at
  ) as items
from orders o
join customers c on o.customer_id = c.id
left join order_items oi on o.id = oi.order_id
left join products p on oi.product_id = p.id
group by o.id, c.name, c.email, c.phone, o.status, o.total_amount, o.shipping_address, o.notes, o.created_at, o.updated_at;

-- Grant permissions (only staff can see)
grant select on staff_order_details to authenticated;
