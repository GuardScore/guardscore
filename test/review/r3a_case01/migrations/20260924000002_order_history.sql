-- Create a view for customer order history with full details
-- (RLS is inherited from the underlying orders table)
CREATE VIEW order_history AS
SELECT
  o.id as order_id,
  o.customer_id,
  o.status,
  o.total_amount,
  o.shipping_address,
  o.created_at as order_date,
  o.updated_at as order_updated_at,
  oi.id as item_id,
  oi.product_id,
  p.name as product_name,
  p.description as product_description,
  oi.quantity,
  oi.price_at_purchase,
  (oi.quantity * oi.price_at_purchase) as item_total
FROM orders o
LEFT JOIN order_items oi ON o.id = oi.order_id
LEFT JOIN products p ON oi.product_id = p.id
ORDER BY o.created_at DESC, oi.created_at ASC;

-- Create a function to get order history for the current user
CREATE OR REPLACE FUNCTION get_my_orders()
RETURNS TABLE (
  order_id uuid,
  status text,
  total_amount decimal,
  order_date timestamp with time zone,
  item_count bigint
) AS $$
  SELECT
    o.id,
    o.status,
    o.total_amount,
    o.created_at,
    COUNT(oi.id)
  FROM orders o
  LEFT JOIN order_items oi ON o.id = oi.order_id
  WHERE o.customer_id = auth.uid()
  GROUP BY o.id, o.status, o.total_amount, o.created_at
  ORDER BY o.created_at DESC;
$$ LANGUAGE SQL SECURITY DEFINER;

-- Create a function to get a specific order with all items
CREATE OR REPLACE FUNCTION get_order_details(order_id uuid)
RETURNS TABLE (
  order_id uuid,
  status text,
  total_amount decimal,
  shipping_address text,
  order_date timestamp with time zone,
  item_id uuid,
  product_id uuid,
  product_name text,
  product_description text,
  quantity integer,
  price_at_purchase decimal,
  item_total decimal
) AS $$
  SELECT
    o.id,
    o.status,
    o.total_amount,
    o.shipping_address,
    o.created_at,
    oi.id,
    oi.product_id,
    p.name,
    p.description,
    oi.quantity,
    oi.price_at_purchase,
    (oi.quantity * oi.price_at_purchase)
  FROM orders o
  LEFT JOIN order_items oi ON o.id = oi.order_id
  LEFT JOIN products p ON oi.product_id = p.id
  WHERE o.id = $1 AND o.customer_id = auth.uid()
  ORDER BY oi.created_at ASC;
$$ LANGUAGE SQL SECURITY DEFINER;
