-- Create reviews table
CREATE TABLE reviews (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  product_id uuid NOT NULL,
  customer_id uuid NOT NULL,
  rating integer NOT NULL,
  title text,
  content text,
  verified_purchase boolean DEFAULT false,
  helpful_count integer DEFAULT 0,
  created_at timestamp with time zone DEFAULT now(),
  updated_at timestamp with time zone DEFAULT now(),
  CONSTRAINT reviews_product_fk FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
  CONSTRAINT reviews_customer_fk FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
  CONSTRAINT reviews_rating_range CHECK (rating >= 1 AND rating <= 5),
  CONSTRAINT reviews_one_per_customer_product UNIQUE (product_id, customer_id)
);

-- Create indexes for performance
CREATE INDEX idx_reviews_product_id ON reviews(product_id);
CREATE INDEX idx_reviews_customer_id ON reviews(customer_id);
CREATE INDEX idx_reviews_rating ON reviews(rating);
CREATE INDEX idx_reviews_created_at ON reviews(created_at DESC);

-- Enable RLS
ALTER TABLE reviews ENABLE ROW LEVEL SECURITY;

-- Reviews are readable by everyone (public)
CREATE POLICY "reviews_readable_by_all" ON reviews
  FOR SELECT USING (true);

-- Authenticated users can create reviews
CREATE POLICY "reviews_insertable_by_authenticated" ON reviews
  FOR INSERT TO authenticated
  WITH CHECK (customer_id = auth.uid());

-- Users can update their own reviews
CREATE POLICY "reviews_updateable_by_owner" ON reviews
  FOR UPDATE TO authenticated
  USING (customer_id = auth.uid())
  WITH CHECK (customer_id = auth.uid());

-- Users can delete their own reviews
CREATE POLICY "reviews_deletable_by_owner" ON reviews
  FOR DELETE TO authenticated
  USING (customer_id = auth.uid());

-- Create function to get product reviews with customer info
CREATE OR REPLACE FUNCTION get_product_reviews(p_product_id uuid)
RETURNS TABLE (
  review_id uuid,
  rating integer,
  title text,
  content text,
  customer_name text,
  verified_purchase boolean,
  helpful_count integer,
  created_at timestamp with time zone
) AS $$
  SELECT
    r.id,
    r.rating,
    r.title,
    r.content,
    c.full_name,
    r.verified_purchase,
    r.helpful_count,
    r.created_at
  FROM reviews r
  JOIN customers c ON r.customer_id = c.id
  WHERE r.product_id = $1
  ORDER BY r.helpful_count DESC, r.created_at DESC;
$$ LANGUAGE SQL SECURITY INVOKER;

-- Create function to get product rating stats
CREATE OR REPLACE FUNCTION get_product_rating_stats(p_product_id uuid)
RETURNS TABLE (
  average_rating numeric,
  total_reviews bigint,
  rating_count_1 bigint,
  rating_count_2 bigint,
  rating_count_3 bigint,
  rating_count_4 bigint,
  rating_count_5 bigint
) AS $$
  SELECT
    ROUND(AVG(rating)::numeric, 2),
    COUNT(*),
    COUNT(CASE WHEN rating = 1 THEN 1 END),
    COUNT(CASE WHEN rating = 2 THEN 1 END),
    COUNT(CASE WHEN rating = 3 THEN 1 END),
    COUNT(CASE WHEN rating = 4 THEN 1 END),
    COUNT(CASE WHEN rating = 5 THEN 1 END)
  FROM reviews
  WHERE product_id = $1;
$$ LANGUAGE SQL SECURITY INVOKER;

-- Create function to get current user's reviews
CREATE OR REPLACE FUNCTION get_my_reviews()
RETURNS TABLE (
  review_id uuid,
  product_id uuid,
  product_name text,
  rating integer,
  title text,
  content text,
  verified_purchase boolean,
  created_at timestamp with time zone
) AS $$
  SELECT
    r.id,
    r.product_id,
    p.name,
    r.rating,
    r.title,
    r.content,
    r.verified_purchase,
    r.created_at
  FROM reviews r
  JOIN products p ON r.product_id = p.id
  WHERE r.customer_id = auth.uid()
  ORDER BY r.created_at DESC;
$$ LANGUAGE SQL SECURITY INVOKER;

-- Create function to verify if customer purchased a product
CREATE OR REPLACE FUNCTION verify_customer_purchase(p_customer_id uuid, p_product_id uuid)
RETURNS boolean AS $$
  SELECT EXISTS(
    SELECT 1
    FROM order_items oi
    JOIN orders o ON oi.order_id = o.id
    WHERE o.customer_id = p_customer_id
      AND oi.product_id = p_product_id
      AND o.status IN ('completed', 'shipped', 'delivered')
  );
$$ LANGUAGE SQL SECURITY INVOKER;

-- Create function to insert review and auto-set verified_purchase
CREATE OR REPLACE FUNCTION create_review(
  p_product_id uuid,
  p_rating integer,
  p_title text,
  p_content text
)
RETURNS TABLE (
  id uuid,
  product_id uuid,
  customer_id uuid,
  rating integer,
  title text,
  content text,
  verified_purchase boolean,
  created_at timestamp with time zone
) AS $$
  INSERT INTO reviews (product_id, customer_id, rating, title, content, verified_purchase)
  VALUES (
    p_product_id,
    auth.uid(),
    p_rating,
    p_title,
    p_content,
    verify_customer_purchase(auth.uid(), p_product_id)
  )
  RETURNING reviews.id, reviews.product_id, reviews.customer_id, reviews.rating, reviews.title, reviews.content, reviews.verified_purchase, reviews.created_at;
$$ LANGUAGE SQL SECURITY INVOKER;
