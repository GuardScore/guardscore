-- Add constraint to prevent negative order amounts
ALTER TABLE orders ADD CONSTRAINT orders_total_amount_not_negative CHECK (total_amount >= 0) NOT VALID;

-- Add constraints to prevent negative prices and quantities
ALTER TABLE products ADD CONSTRAINT products_price_not_negative CHECK (price >= 0) NOT VALID;
ALTER TABLE order_items ADD CONSTRAINT order_items_quantity_positive CHECK (quantity > 0) NOT VALID;
ALTER TABLE order_items ADD CONSTRAINT order_items_price_not_negative CHECK (price_at_purchase >= 0) NOT VALID;
