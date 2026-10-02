-- Reviews table
create table reviews (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references products(id) on delete cascade,
  customer_id uuid not null references customers(id) on delete cascade,
  rating integer not null check (rating >= 1 and rating <= 5),
  title text not null,
  content text,
  helpful_count integer not null default 0 check (helpful_count >= 0),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(product_id, customer_id)
);

-- Indexes for performance
create index idx_reviews_product_id on reviews(product_id);
create index idx_reviews_customer_id on reviews(customer_id);
create index idx_reviews_rating on reviews(rating);
create index idx_reviews_created_at on reviews(created_at desc);

-- Enable RLS
alter table reviews enable row level security;

-- RLS Policies for Reviews
-- Anyone can view published reviews
create policy "Anyone can view reviews"
  on reviews for select
  using (true);

-- Authenticated users can create reviews
create policy "Authenticated users can create reviews"
  on reviews for insert
  with check (auth.uid() = customer_id);

-- Users can update their own reviews
create policy "Users can update their own reviews"
  on reviews for update
  using (auth.uid() = customer_id)
  with check (auth.uid() = customer_id);

-- Users can delete their own reviews
create policy "Users can delete their own reviews"
  on reviews for delete
  using (auth.uid() = customer_id);

-- Staff can delete any review (for moderation)
create policy "Staff can delete any review"
  on reviews for delete
  using (is_staff_or_admin());
