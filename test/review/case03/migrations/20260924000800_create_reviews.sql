-- Create reviews table
create table reviews (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references products(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  customer_id uuid not null references customers(id) on delete cascade,
  rating integer not null check (rating >= 1 and rating <= 5),
  title text not null,
  content text not null,
  helpful_count integer not null default 0 check (helpful_count >= 0),
  unhelpful_count integer not null default 0 check (unhelpful_count >= 0),
  verified_purchase boolean not null default false,
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now()
);

-- Enable RLS
alter table reviews enable row level security;

-- Everyone can read reviews
create policy "reviews_are_readable_by_all"
  on reviews
  for select
  to public
  using (true);

-- Users can create reviews only if they bought the product
create policy "users_can_create_reviews_for_purchased_products"
  on reviews
  for insert
  to authenticated
  with check (
    user_id = auth.uid()
    and verified_purchase = false  -- will be set by trigger if user purchased
    and customer_id = (select id from customers where user_id = auth.uid())
  );

-- Users can update their own reviews
create policy "users_can_update_own_reviews"
  on reviews
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (
    auth.uid() = user_id
    and product_id = (select product_id from reviews where id = reviews.id)
    and customer_id = (select customer_id from reviews where id = reviews.id)
  );

-- Users can delete their own reviews
create policy "users_can_delete_own_reviews"
  on reviews
  for delete
  to authenticated
  using (auth.uid() = user_id);

-- Staff can update verified_purchase flag
create policy "staff_can_verify_purchases"
  on reviews
  for update
  to authenticated
  using (is_staff())
  with check (is_staff());

-- Create indexes
create index reviews_product_id_idx on reviews(product_id);
create index reviews_user_id_idx on reviews(user_id);
create index reviews_rating_idx on reviews(rating);
create index reviews_verified_purchase_idx on reviews(verified_purchase);
create index reviews_created_at_idx on reviews(created_at desc);

-- Create trigger to update updated_at
create trigger update_reviews_updated_at
before update on reviews
for each row
execute function update_updated_at_column();

-- Create function to verify purchase
create or replace function verify_purchase_on_review()
returns trigger as $$
begin
  -- Check if user has purchased this product
  if exists(
    select 1 from order_items oi
    join orders o on oi.order_id = o.id
    where oi.product_id = new.product_id
    and o.user_id = new.user_id
    and o.status != 'cancelled'
  ) then
    new.verified_purchase := true;
  end if;
  return new;
end;
$$ language plpgsql;

-- Create trigger to verify purchase
create trigger verify_purchase_before_insert
before insert on reviews
for each row
execute function verify_purchase_on_review();
