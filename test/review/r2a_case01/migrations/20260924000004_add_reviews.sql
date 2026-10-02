-- Reviews table
create table public.reviews (
  id uuid primary key default uuid_generate_v4(),
  product_id uuid not null references public.products(id) on delete cascade,
  customer_id uuid not null references public.customers(id) on delete cascade,
  rating integer not null check (rating >= 1 and rating <= 5),
  title text not null,
  content text,
  helpful_count integer not null default 0 check (helpful_count >= 0),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(product_id, customer_id)
);

-- Enable RLS
alter table public.reviews enable row level security;

-- Anyone can read reviews
create policy "anyone_can_read_reviews" on public.reviews
  for select using (true);

-- Authenticated users can create reviews (one per product per customer)
create policy "users_can_create_reviews" on public.reviews
  for insert with check (
    auth.uid() is not null
    and customer_id in (
      select id from public.customers where user_id = auth.uid()
    )
  );

-- Users can only update their own reviews
create policy "users_can_update_own_reviews" on public.reviews
  for update using (
    customer_id in (
      select id from public.customers where user_id = auth.uid()
    )
  )
  with check (
    customer_id in (
      select id from public.customers where user_id = auth.uid()
    )
  );

-- Users can only delete their own reviews
create policy "users_can_delete_own_reviews" on public.reviews
  for delete using (
    customer_id in (
      select id from public.customers where user_id = auth.uid()
    )
  );

-- Staff can read and moderate reviews
create policy "staff_can_read_all_reviews" on public.reviews
  for select using (auth.jwt() ->> 'role' in ('admin', 'staff'));

create policy "staff_can_delete_reviews" on public.reviews
  for delete using (auth.jwt() ->> 'role' in ('admin', 'staff'));

-- Indexes
create index idx_reviews_product_id on public.reviews(product_id);
create index idx_reviews_customer_id on public.reviews(customer_id);
create index idx_reviews_created_at on public.reviews(created_at desc);
create index idx_reviews_rating on public.reviews(rating);

-- Helper function to get product reviews with average rating
create or replace function public.get_product_reviews(p_product_id uuid)
returns table (
  id uuid,
  customer_name text,
  rating integer,
  title text,
  content text,
  helpful_count integer,
  created_at timestamp with time zone
) as $$
select
  r.id,
  c.first_name || ' ' || c.last_name,
  r.rating,
  r.title,
  r.content,
  r.helpful_count,
  r.created_at
from public.reviews r
join public.customers c on r.customer_id = c.id
where r.product_id = p_product_id
order by r.helpful_count desc, r.created_at desc;
$$ language sql security definer;

-- Helper function to get product rating summary
create or replace function public.get_product_rating_summary(p_product_id uuid)
returns table (
  average_rating numeric,
  total_reviews integer,
  rating_1_count integer,
  rating_2_count integer,
  rating_3_count integer,
  rating_4_count integer,
  rating_5_count integer
) as $$
select
  round(avg(rating)::numeric, 2),
  count(*)::integer,
  (select count(*) from public.reviews where product_id = p_product_id and rating = 1)::integer,
  (select count(*) from public.reviews where product_id = p_product_id and rating = 2)::integer,
  (select count(*) from public.reviews where product_id = p_product_id and rating = 3)::integer,
  (select count(*) from public.reviews where product_id = p_product_id and rating = 4)::integer,
  (select count(*) from public.reviews where product_id = p_product_id and rating = 5)::integer
from public.reviews
where product_id = p_product_id;
$$ language sql security definer;

-- Helper function for users to post a review
create or replace function public.post_review(
  p_product_id uuid,
  p_rating integer,
  p_title text,
  p_content text
)
returns table (
  id uuid,
  rating integer,
  title text,
  created_at timestamp with time zone
) as $$
insert into public.reviews (product_id, customer_id, rating, title, content)
select
  p_product_id,
  c.id,
  p_rating,
  p_title,
  p_content
from public.customers c
where c.user_id = auth.uid()
on conflict (product_id, customer_id) do update
set
  rating = p_rating,
  title = p_title,
  content = p_content,
  updated_at = now()
returning id, rating, title, created_at;
$$ language sql security definer;

-- Grant permissions
grant execute on function public.get_product_reviews(uuid) to anon, authenticated;
grant execute on function public.get_product_rating_summary(uuid) to anon, authenticated;
grant execute on function public.post_review(uuid, integer, text, text) to authenticated;
