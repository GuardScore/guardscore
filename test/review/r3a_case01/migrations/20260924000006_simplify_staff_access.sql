-- Drop the staff-specific select policy (causes RLS conflicts)
DROP POLICY IF EXISTS "orders_select_staff" ON orders;

-- Update the staff update policy to be more restrictive - only via function
DROP POLICY IF EXISTS "orders_update_staff" ON orders;

-- Keep customer policies simple and unchanged
-- Customer can only see/update their own orders (RLS enforced)

-- Recreate the update function with security definer but with strict staff check
DROP FUNCTION IF EXISTS update_order_status(uuid, text);
CREATE FUNCTION update_order_status(
  p_order_id uuid,
  p_new_status text
)
RETURNS TABLE (
  id uuid,
  customer_id uuid,
  status text,
  total_amount decimal,
  updated_at timestamp with time zone
) AS $$
BEGIN
  -- Check staff status first
  IF NOT is_staff() THEN
    RAISE EXCEPTION 'permission denied: only staff can update order status';
  END IF;

  -- Update the order
  RETURN QUERY
  UPDATE orders
  SET status = p_new_status, updated_at = now()
  WHERE id = p_order_id
  RETURNING orders.id, orders.customer_id, orders.status, orders.total_amount, orders.updated_at;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Recreate get_all_orders with explicit staff check using SECURITY INVOKER
DROP FUNCTION IF EXISTS get_all_orders();
CREATE FUNCTION get_all_orders()
RETURNS TABLE (
  order_id uuid,
  customer_id uuid,
  customer_email text,
  status text,
  total_amount decimal,
  item_count bigint,
  order_date timestamp with time zone
) AS $$
  -- This function requires the caller to be staff
  -- The is_staff() check below will raise if they're not
  WITH staff_check AS (
    SELECT CASE WHEN is_staff() THEN 1 ELSE 0 END as allowed
  )
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
  CROSS JOIN staff_check
  WHERE staff_check.allowed = 1
  GROUP BY o.id, o.customer_id, c.email, o.status, o.total_amount, o.created_at
  ORDER BY o.created_at DESC;
$$ LANGUAGE SQL SECURITY INVOKER;

-- Recreate get_order_for_staff with explicit staff check
DROP FUNCTION IF EXISTS get_order_for_staff(uuid);
CREATE FUNCTION get_order_for_staff(p_order_id uuid)
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
BEGIN
  -- Check staff status first
  IF NOT is_staff() THEN
    RAISE EXCEPTION 'permission denied: only staff can view order details';
  END IF;

  -- Return order details
  RETURN QUERY
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
  WHERE o.id = p_order_id
  ORDER BY oi.created_at ASC;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Update prevent_customer_order_changes trigger
DROP TRIGGER IF EXISTS prevent_customer_order_changes_trigger ON orders;
DROP FUNCTION IF EXISTS prevent_customer_order_changes();

CREATE FUNCTION prevent_customer_order_changes()
RETURNS trigger AS $$
BEGIN
  -- Only apply restriction if NOT staff
  IF NOT COALESCE(is_staff(), false) THEN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
      RAISE EXCEPTION 'permission denied: only staff can change order status';
    END IF;
    IF NEW.total_amount IS DISTINCT FROM OLD.total_amount THEN
      RAISE EXCEPTION 'permission denied: only staff can change order total amount';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER prevent_customer_order_changes_trigger
  BEFORE UPDATE ON orders
  FOR EACH ROW
  EXECUTE FUNCTION prevent_customer_order_changes();
