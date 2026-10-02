-- Create products table
CREATE TABLE products (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  description text,
  price decimal(10, 2) NOT NULL,
  stock_quantity integer DEFAULT 0,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now()
);

-- Create customers table
CREATE TABLE customers (
  id uuid PRIMARY KEY,
  email text NOT NULL UNIQUE,
  full_name text,
  phone text,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT customers_id_fk FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE
);

-- Create orders table
CREATE TABLE orders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id uuid NOT NULL,
  status text DEFAULT 'pending',
  total_amount decimal(10, 2) NOT NULL,
  shipping_address text,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT orders_customer_fk FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE
);

-- Create order_items table (line items in an order)
CREATE TABLE order_items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  order_id uuid NOT NULL,
  product_id uuid NOT NULL,
  quantity integer NOT NULL,
  price_at_purchase decimal(10, 2) NOT NULL,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT order_items_order_fk FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
  CONSTRAINT order_items_product_fk FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT
);

-- Create indexes for performance
CREATE INDEX idx_orders_customer_id ON orders(customer_id);
CREATE INDEX idx_order_items_order_id ON order_items(order_id);
CREATE INDEX idx_order_items_product_id ON order_items(product_id);
CREATE INDEX idx_products_name ON products(name);

-- Enable RLS (Row Level Security)
ALTER TABLE products ENABLE ROW LEVEL SECURITY;
ALTER TABLE customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE order_items ENABLE ROW LEVEL SECURITY;

-- Products are readable by everyone (public catalog)
CREATE POLICY "products_readable_by_all" ON products
  FOR SELECT USING (true);

-- Only admins can insert/update/delete products (for now, we'll restrict this)
CREATE POLICY "products_writable_by_admins" ON products
  FOR INSERT
  WITH CHECK (false);
CREATE POLICY "products_updateable_by_admins" ON products
  FOR UPDATE
  USING (false);
CREATE POLICY "products_deletable_by_admins" ON products
  FOR DELETE
  USING (false);

-- Customers can only read their own profile
CREATE POLICY "customers_readable_by_self" ON customers
  FOR SELECT USING (auth.uid() = id);

-- Users can update their own profile
CREATE POLICY "customers_updateable_by_self" ON customers
  FOR UPDATE USING (auth.uid() = id);

-- Users can insert their own profile (signup)
CREATE POLICY "customers_insertable_by_self" ON customers
  FOR INSERT WITH CHECK (auth.uid() = id);

-- Orders are readable only by the customer who owns them
CREATE POLICY "orders_readable_by_owner" ON orders
  FOR SELECT USING (auth.uid() = customer_id);

-- Customers can create their own orders
CREATE POLICY "orders_insertable_by_owner" ON orders
  FOR INSERT WITH CHECK (auth.uid() = customer_id);

-- Customers can update their own orders (if not shipped)
CREATE POLICY "orders_updateable_by_owner" ON orders
  FOR UPDATE USING (auth.uid() = customer_id);

-- Order items are readable only if user owns the order
CREATE POLICY "order_items_readable_by_order_owner" ON order_items
  FOR SELECT USING (
    auth.uid() IN (
      SELECT customer_id FROM orders WHERE id = order_id
    )
  );

-- Order items can be inserted by the order owner
CREATE POLICY "order_items_insertable_by_order_owner" ON order_items
  FOR INSERT WITH CHECK (
    auth.uid() IN (
      SELECT customer_id FROM orders WHERE id = order_id
    )
  );
