-- Create reviews table
create table if not exists public.reviews (
  id uuid primary key default uuid_generate_v4(),
  product_id uuid not null references public.products on delete cascade,
  customer_id uuid not null references public.profiles on delete cascade,
  rating integer not null check (rating >= 1 and rating <= 5),
  title text,
  content text not null,
  is_approved boolean default true,
  helpful_count integer default 0 check (helpful_count >= 0),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(product_id, customer_id)
);

-- Create indexes for better query performance
create index if not exists idx_reviews_product_id on public.reviews(product_id);
create index if not exists idx_reviews_customer_id on public.reviews(customer_id);
create index if not exists idx_reviews_rating on public.reviews(rating);
create index if not exists idx_reviews_created_at on public.reviews(created_at desc);
create index if not exists idx_reviews_is_approved on public.reviews(is_approved);

-- Enable RLS
alter table public.reviews enable row level security;

-- Reviews policies
create policy "Anyone can view approved reviews" on public.reviews
  for select using (is_approved = true);

create policy "Customers can view their own unapproved reviews" on public.reviews
  for select using (
    is_approved = true
    or customer_id = auth.uid()
  );

create policy "Authenticated users can create reviews" on public.reviews
  for insert with check (
    auth.uid() = customer_id
    and auth.uid() is not null
  );

create policy "Customers can update their own reviews" on public.reviews
  for update using (auth.uid() = customer_id);

create policy "Customers can delete their own reviews" on public.reviews
  for delete using (auth.uid() = customer_id);

create policy "Staff can view and approve all reviews" on public.reviews
  for select using (
    is_approved = true
    or exists (
      select 1 from public.profiles
      where id = auth.uid()
      and role in ('staff', 'admin')
    )
  );

create policy "Staff can update review approval status" on public.reviews
  for update using (
    exists (
      select 1 from public.profiles
      where id = auth.uid()
      and role in ('staff', 'admin')
    )
  );

-- Function to update review updated_at timestamp
create or replace function public.update_review_timestamp()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger update_reviews_timestamp before update on public.reviews
  for each row execute procedure update_review_timestamp();

-- Function to calculate product average rating
create or replace function public.get_product_average_rating(product_id uuid)
returns numeric as $$
declare
  avg_rating numeric;
begin
  select avg(rating) into avg_rating
  from public.reviews
  where reviews.product_id = get_product_average_rating.product_id
  and is_approved = true;

  return coalesce(avg_rating, 0);
end;
$$ language plpgsql;

-- Sample reviews for testing
insert into public.reviews (product_id, customer_id, rating, title, content, is_approved)
select
  p.id,
  prof.id,
  (floor(random() * 2) + 4)::integer,
  case
    when floor(random() * 3) = 0 then 'Great product!'
    when floor(random() * 3) = 1 then 'Very satisfied'
    else 'Highly recommend'
  end,
  case
    when floor(random() * 3) = 0 then 'This product exceeded my expectations. Highly recommend to anyone looking for quality.'
    when floor(random() * 3) = 1 then 'Great value for the price. Works as advertised and arrived on time.'
    else 'Perfect! This is exactly what I needed. Very happy with this purchase.'
  end,
  true
from public.products p
cross join (
  select distinct on (id) id from public.profiles where role = 'customer' limit 2
) prof
limit 5
on conflict do nothing;
