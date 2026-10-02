-- Create product_reviews table
create table if not exists product_reviews (
  id bigserial primary key,
  product_id bigint not null references products(id) on delete cascade,
  customer_id bigint not null references customers(id) on delete cascade,
  rating integer not null check (rating >= 1 and rating <= 5),
  title text,
  review text,
  helpful_count integer default 0,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null,
  unique(product_id, customer_id)
);

-- Create indexes for better query performance
create index if not exists product_reviews_product_id_idx on product_reviews(product_id);
create index if not exists product_reviews_customer_id_idx on product_reviews(customer_id);
create index if not exists product_reviews_rating_idx on product_reviews(rating);
create index if not exists product_reviews_created_at_idx on product_reviews(created_at);

-- Enable RLS on product_reviews
alter table product_reviews enable row level security;

-- RLS Policy: Reviews are publicly readable
create policy "Reviews are publicly readable" on product_reviews
  for select using (true);

-- RLS Policy: Authenticated users can insert reviews
create policy "Authenticated users can create reviews" on product_reviews
  for insert with check (
    auth.role() = 'authenticated' and
    customer_id in (
      select id from customers where user_id = auth.uid()
    )
  );

-- RLS Policy: Users can only update their own reviews
create policy "Users can update own reviews" on product_reviews
  for update using (
    customer_id in (
      select id from customers where user_id = auth.uid()
    )
  ) with check (
    customer_id in (
      select id from customers where user_id = auth.uid()
    )
  );

-- RLS Policy: Users can only delete their own reviews
create policy "Users can delete own reviews" on product_reviews
  for delete using (
    customer_id in (
      select id from customers where user_id = auth.uid()
    )
  );

-- Create a function to get average rating for a product
create or replace function get_product_average_rating(product_id bigint)
returns decimal as $$
  select coalesce(avg(rating)::decimal, 0)
  from product_reviews
  where product_id = $1;
$$ language sql;

-- Create a function to get review count for a product
create or replace function get_product_review_count(product_id bigint)
returns bigint as $$
  select count(*)
  from product_reviews
  where product_id = $1;
$$ language sql;
