-- Create reviews table
create table reviews (
  id bigserial primary key,
  product_id bigint not null references products on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  rating integer not null check (rating >= 1 and rating <= 5),
  title text,
  content text,
  helpful_count integer default 0 check (helpful_count >= 0),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(product_id, user_id)
);

-- Create index for efficient queries
create index idx_reviews_product_id on reviews(product_id);
create index idx_reviews_user_id on reviews(user_id);
create index idx_reviews_created_at on reviews(created_at desc);

-- Enable RLS
alter table reviews enable row level security;

-- RLS: Everyone can read published reviews
create policy "Reviews are publicly readable"
  on reviews for select
  using (true);

-- RLS: Users can create reviews
create policy "Users can create reviews"
  on reviews for insert
  to authenticated
  with check (auth.uid() = user_id);

-- RLS: Users can update their own reviews
create policy "Users can update their own reviews"
  on reviews for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- RLS: Users can delete their own reviews, staff can delete any
create policy "Users can delete their own reviews"
  on reviews for delete
  to authenticated
  using (auth.uid() = user_id or is_staff(auth.uid()));

-- Lock helpful_count and rating so users can't manipulate them
create or replace function lock_reviews_fields()
returns trigger language plpgsql as $lock$
begin
  if current_user in ('anon', 'authenticated') and pg_trigger_depth() = 1 then
    if tg_op = 'INSERT' then
      new."helpful_count" := 0;
    else
      if new."helpful_count" is distinct from old."helpful_count" then
        raise exception 'permission denied: helpful_count can only be changed by the server';
      end if;
      if new."rating" is distinct from old."rating" then
        raise exception 'permission denied: rating cannot be changed after review is posted';
      end if;
    end if;
  end if;
  return new;
end $lock$;

drop trigger if exists "lock_reviews_fields" on reviews;
create trigger "lock_reviews_fields" before insert or update on reviews for each row execute function lock_reviews_fields();

-- Create a view for product reviews with user info (but no email)
create view product_reviews as
select
  r.id,
  r.product_id,
  r.user_id,
  r.rating,
  r.title,
  r.content,
  r.helpful_count,
  r.created_at,
  r.updated_at
from reviews r
where true
order by r.created_at desc;

alter view product_reviews set (security_invoker = true);

-- Create a summary stats view for products
create view product_review_stats as
select
  p.id as product_id,
  count(r.id) as review_count,
  round(avg(r.rating)::numeric, 2) as average_rating,
  count(case when r.rating = 5 then 1 end) as five_star_count,
  count(case when r.rating = 4 then 1 end) as four_star_count,
  count(case when r.rating = 3 then 1 end) as three_star_count,
  count(case when r.rating = 2 then 1 end) as two_star_count,
  count(case when r.rating = 1 then 1 end) as one_star_count
from products p
left join reviews r on p.id = r.product_id
group by p.id;

alter view product_review_stats set (security_invoker = true);
