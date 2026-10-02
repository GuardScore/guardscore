-- Drop all existing orders policies to rebuild them correctly
DROP POLICY IF EXISTS "orders_readable_by_owner" ON orders;
DROP POLICY IF EXISTS "orders_insertable_by_owner" ON orders;
DROP POLICY IF EXISTS "orders_updateable_by_owner" ON orders;
DROP POLICY IF EXISTS "orders_readable_by_staff" ON orders;
DROP POLICY IF EXISTS "orders_status_updateable_by_staff" ON orders;

-- Customers can select their own orders
CREATE POLICY "orders_select_own" ON orders
  FOR SELECT TO authenticated
  USING (customer_id = auth.uid());

-- Customers can insert their own orders
CREATE POLICY "orders_insert_own" ON orders
  FOR INSERT TO authenticated
  WITH CHECK (customer_id = auth.uid());

-- Customers can update their own orders (but trigger prevents status/amount changes)
CREATE POLICY "orders_update_own" ON orders
  FOR UPDATE TO authenticated
  USING (customer_id = auth.uid())
  WITH CHECK (customer_id = auth.uid());

-- Staff can select all orders
CREATE POLICY "orders_select_staff" ON orders
  FOR SELECT TO authenticated
  USING (is_staff());

-- Staff can update all orders (but trigger prevents unwanted changes)
CREATE POLICY "orders_update_staff" ON orders
  FOR UPDATE TO authenticated
  USING (is_staff())
  WITH CHECK (is_staff());

-- Trigger to prevent customers from changing status and total_amount
CREATE OR REPLACE FUNCTION prevent_customer_order_changes()
RETURNS trigger AS $$
BEGIN
  IF current_user IN ('anon', 'authenticated') AND pg_trigger_depth() = 1 AND NOT COALESCE(is_staff(), false) THEN
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

-- Create trigger on orders table
DROP TRIGGER IF EXISTS prevent_customer_order_changes_trigger ON orders;
CREATE TRIGGER prevent_customer_order_changes_trigger
  BEFORE UPDATE ON orders
  FOR EACH ROW
  EXECUTE FUNCTION prevent_customer_order_changes();

-- Change functions to use security invoker so RLS applies
ALTER FUNCTION get_all_orders() SECURITY INVOKER;
ALTER FUNCTION update_order_status(uuid, text) SECURITY INVOKER;
ALTER FUNCTION get_order_for_staff(uuid) SECURITY INVOKER;
