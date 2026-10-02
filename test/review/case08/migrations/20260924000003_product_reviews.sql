-- Create reviews table
create table if not exists reviews (
  id bigserial primary key,
  product_id bigint references products(id) on delete cascade not null,
  customer_id bigint references customers(id) on delete cascade not null,
  rating integer not null check (rating >= 1 and rating <= 5),
  title text not null,
  text text not null,
  verified_purchase boolean default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(product_id, customer_id)
);

-- Enable RLS on reviews
alter table reviews enable row level security;

-- Create indexes for performance
create index if not exists idx_reviews_product_id on reviews(product_id);
create index if not exists idx_reviews_customer_id on reviews(customer_id);
create index if not exists idx_reviews_rating on reviews(rating);

-- Trigger to set verified_purchase based on order history
create or replace function set_verified_purchase()
returns trigger as $$
begin
  new.verified_purchase := exists (
    select 1 from order_items oi
    join orders o on oi.order_id = o.id
    where oi.product_id = new.product_id
    and o.customer_id = new.customer_id
    and o.status in ('delivered', 'shipped', 'processing')
  );
  return new;
end;
$$ language plpgsql;

create trigger reviews_set_verified_purchase
  before insert or update on reviews
  for each row
  execute function set_verified_purchase();

-- RLS Policies

-- Anyone can view reviews
create policy "Reviews are viewable by everyone"
  on reviews for select
  using (true);

-- Customers can create reviews
create policy "Customers can create reviews"
  on reviews for insert
  with check (
    customer_id = (select id from customers where user_id = auth.uid())
  );

-- Customers can only update their own reviews
create policy "Customers can update their own reviews"
  on reviews for update
  using (
    customer_id = (select id from customers where user_id = auth.uid())
  )
  with check (
    customer_id = (select id from customers where user_id = auth.uid())
  );

-- Customers can only delete their own reviews
create policy "Customers can delete their own reviews"
  on reviews for delete
  using (
    customer_id = (select id from customers where user_id = auth.uid())
  );

-- Staff can delete inappropriate reviews
create policy "Staff can delete reviews"
  on reviews for delete
  using (
    is_staff(auth.uid())
  );

-- Create a view for product review stats
create view product_review_stats with (security_invoker = true) as
  select
    p.id as product_id,
    p.name,
    count(r.id) as review_count,
    round(avg(r.rating)::numeric, 2) as average_rating,
    count(case when r.rating = 5 then 1 end) as five_star_count,
    count(case when r.rating = 4 then 1 end) as four_star_count,
    count(case when r.rating = 3 then 1 end) as three_star_count,
    count(case when r.rating = 2 then 1 end) as two_star_count,
    count(case when r.rating = 1 then 1 end) as one_star_count
  from products p
  left join reviews r on p.id = r.product_id
  group by p.id, p.name;
