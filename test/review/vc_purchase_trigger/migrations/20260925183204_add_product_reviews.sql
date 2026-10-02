-- Create reviews table
create table product_reviews (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references products on delete cascade,
  customer_id uuid not null references customer_profiles on delete cascade,
  rating integer not null check (rating >= 1 and rating <= 5),
  title text not null,
  content text,
  helpful_count integer not null default 0 check (helpful_count >= 0),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create indexes for performance
create index idx_product_reviews_product_id on product_reviews(product_id);
create index idx_product_reviews_customer_id on product_reviews(customer_id);
create index idx_product_reviews_rating on product_reviews(rating);
create index idx_product_reviews_created_at on product_reviews(created_at);

-- Create unique constraint: one review per customer per product
create unique index idx_one_review_per_customer_product
  on product_reviews(product_id, customer_id);

-- Enable RLS
alter table product_reviews enable row level security;

-- Reviews are public (anyone can read)
create policy "reviews are public" on product_reviews
  for select using (true);

-- Customers can create reviews (validation in trigger)
create policy "customers can create reviews" on product_reviews
  for insert with check (auth.uid() = customer_id);

-- Customers can update their own reviews
create policy "customers can update own reviews" on product_reviews
  for update using (auth.uid() = customer_id);

-- Customers can delete their own reviews
create policy "customers can delete own reviews" on product_reviews
  for delete using (auth.uid() = customer_id);

-- Staff can delete reviews (moderation)
create policy "staff can delete reviews" on product_reviews
  for delete using (is_staff());

-- Validate purchase before allowing review insert
create or replace function validate_review_purchase() returns trigger language plpgsql as $validate$
begin
  if not exists (
    select 1 from order_items oi
    join orders o on oi.order_id = o.id
    where oi.product_id = new.product_id
    and o.customer_id = new.customer_id
    and o.status in ('confirmed', 'shipped', 'delivered')
  ) then
    raise exception 'you must purchase this product before reviewing it';
  end if;
  return new;
end $validate$;

drop trigger if exists validate_review_purchase on product_reviews;
create trigger validate_review_purchase before insert on product_reviews
  for each row execute function validate_review_purchase();

-- Lock helpful_count so only staff can change it
create or replace function vc_lock_review_helpful_count() returns trigger language plpgsql as $lock$
begin
  if not is_staff() and current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 then
    if tg_op = 'UPDATE' then
      if new."helpful_count" is distinct from old."helpful_count" then
        raise exception 'permission denied: only staff can update helpful_count';
      end if;
    end if;
  end if;
  return new;
end $lock$;

drop trigger if exists vc_lock_review_helpful_count on product_reviews;
create trigger vc_lock_review_helpful_count before insert or update on product_reviews
  for each row execute function vc_lock_review_helpful_count();

-- Create function to get product reviews with stats
create or replace function get_product_reviews(product_id_param uuid)
returns table (
  review_id uuid,
  customer_name text,
  rating integer,
  title text,
  content text,
  helpful_count integer,
  created_at timestamp with time zone,
  days_ago integer
) as $$
  select
    pr.id,
    cp.full_name,
    pr.rating,
    pr.title,
    pr.content,
    pr.helpful_count,
    pr.created_at,
    extract(day from now() - pr.created_at)::integer
  from product_reviews pr
  join customer_profiles cp on pr.customer_id = cp.id
  where pr.product_id = product_id_param
  order by pr.helpful_count desc, pr.created_at desc;
$$ language sql;

-- Create function to get product rating summary
create or replace function get_product_rating_summary(product_id_param uuid)
returns table (
  total_reviews bigint,
  average_rating decimal,
  five_star_count bigint,
  four_star_count bigint,
  three_star_count bigint,
  two_star_count bigint,
  one_star_count bigint
) as $$
  select
    count(*)::bigint,
    round(avg(rating)::numeric, 2),
    count(*) filter (where rating = 5)::bigint,
    count(*) filter (where rating = 4)::bigint,
    count(*) filter (where rating = 3)::bigint,
    count(*) filter (where rating = 2)::bigint,
    count(*) filter (where rating = 1)::bigint
  from product_reviews
  where product_id = product_id_param;
$$ language sql;

-- Create function for customers to submit a review
create or replace function submit_product_review(
  product_id_param uuid,
  rating_param integer,
  title_param text,
  content_param text
)
returns product_reviews as $$
declare
  new_review product_reviews;
begin
  if rating_param < 1 or rating_param > 5 then
    raise exception 'invalid rating: must be between 1 and 5';
  end if;

  if title_param is null or title_param = '' then
    raise exception 'title cannot be empty';
  end if;

  -- Check if product exists
  if not exists (select 1 from products where id = product_id_param) then
    raise exception 'product not found';
  end if;

  -- Check if customer purchased this product
  if not exists (
    select 1 from order_items oi
    join orders o on oi.order_id = o.id
    where oi.product_id = product_id_param
    and o.customer_id = auth.uid()
    and o.status in ('confirmed', 'shipped', 'delivered')
  ) then
    raise exception 'you must purchase this product before reviewing it';
  end if;

  insert into product_reviews (product_id, customer_id, rating, title, content)
  values (product_id_param, auth.uid(), rating_param, title_param, content_param)
  on conflict (product_id, customer_id)
  do update set
    rating = rating_param,
    title = title_param,
    content = content_param,
    updated_at = now()
  returning * into new_review;

  return new_review;
end;
$$ language plpgsql security definer;

-- Create function for staff to mark reviews as helpful
create or replace function mark_review_helpful(
  review_id_param uuid,
  is_helpful boolean
)
returns product_reviews as $$
declare
  updated_review product_reviews;
begin
  if not is_staff() then
    raise exception 'permission denied: only staff can mark reviews as helpful';
  end if;

  update product_reviews
  set helpful_count = case when is_helpful then helpful_count + 1 else helpful_count end,
      updated_at = now()
  where id = review_id_param
  returning * into updated_review;

  return updated_review;
end;
$$ language plpgsql security definer;
