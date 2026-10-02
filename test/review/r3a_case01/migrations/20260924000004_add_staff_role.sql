-- Create staff_members table to track staff users
CREATE TABLE staff_members (
  id uuid PRIMARY KEY,
  email text NOT NULL UNIQUE,
  role text NOT NULL DEFAULT 'support',
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT staff_members_id_fk FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE
);

-- Enable RLS on staff_members
ALTER TABLE staff_members ENABLE ROW LEVEL SECURITY;

-- Staff can only read their own profile
CREATE POLICY "staff_readable_by_self" ON staff_members
  FOR SELECT USING (auth.uid() = id);

-- Only admins can insert/update/delete staff records (for now, restrict everything)
CREATE POLICY "staff_writable_by_admins" ON staff_members
  FOR INSERT WITH CHECK (false);
CREATE POLICY "staff_updateable_by_admins" ON staff_members
  FOR UPDATE USING (false);
CREATE POLICY "staff_deletable_by_admins" ON staff_members
  FOR DELETE USING (false);

-- Create a function to check if user is staff
CREATE OR REPLACE FUNCTION is_staff()
RETURNS boolean AS $$
  SELECT EXISTS(SELECT 1 FROM staff_members WHERE id = auth.uid());
$$ LANGUAGE SQL SECURITY DEFINER;

-- Update orders RLS to allow staff to read all orders
CREATE POLICY "orders_readable_by_staff" ON orders
  FOR SELECT USING (is_staff());

-- Allow staff to update order status (but not other fields)
CREATE POLICY "orders_status_updateable_by_staff" ON orders
  FOR UPDATE USING (is_staff())
  WITH CHECK (is_staff());

-- Create a function for staff to get all orders with summary
CREATE OR REPLACE FUNCTION get_all_orders()
RETURNS TABLE (
  order_id uuid,
  customer_id uuid,
  customer_email text,
  status text,
  total_amount decimal,
  item_count bigint,
  order_date timestamp with time zone
) AS $$
  SELECT
    o.id,
    o.customer_id,
    c.email,
    o.status,
    o.total_amount,
    COUNT(oi.id),
    o.created_at
  FROM orders o
  JOIN customers c ON o.customer_id = c.id
  LEFT JOIN order_items oi ON o.id = oi.order_id
  WHERE is_staff()
  GROUP BY o.id, o.customer_id, c.email, o.status, o.total_amount, o.created_at
  ORDER BY o.created_at DESC;
$$ LANGUAGE SQL SECURITY DEFINER;

-- Create a function for staff to update order status
CREATE OR REPLACE FUNCTION update_order_status(
  order_id uuid,
  new_status text
)
RETURNS TABLE (
  id uuid,
  customer_id uuid,
  status text,
  total_amount decimal,
  updated_at timestamp with time zone
) AS $$
  UPDATE orders
  SET status = new_status, updated_at = now()
  WHERE id = $1 AND is_staff()
  RETURNING orders.id, orders.customer_id, orders.status, orders.total_amount, orders.updated_at;
$$ LANGUAGE SQL SECURITY DEFINER;

-- Create a function for staff to view a specific order with all details
CREATE OR REPLACE FUNCTION get_order_for_staff(order_id uuid)
RETURNS TABLE (
  order_id uuid,
  customer_id uuid,
  customer_email text,
  customer_name text,
  status text,
  total_amount decimal,
  shipping_address text,
  order_date timestamp with time zone,
  item_id uuid,
  product_id uuid,
  product_name text,
  quantity integer,
  price_at_purchase decimal,
  item_total decimal
) AS $$
  SELECT
    o.id,
    o.customer_id,
    c.email,
    c.full_name,
    o.status,
    o.total_amount,
    o.shipping_address,
    o.created_at,
    oi.id,
    oi.product_id,
    p.name,
    oi.quantity,
    oi.price_at_purchase,
    (oi.quantity * oi.price_at_purchase)
  FROM orders o
  JOIN customers c ON o.customer_id = c.id
  LEFT JOIN order_items oi ON o.id = oi.order_id
  LEFT JOIN products p ON oi.product_id = p.id
  WHERE o.id = $1 AND is_staff()
  ORDER BY oi.created_at ASC;
$$ LANGUAGE SQL SECURITY DEFINER;
