-- Create view for product reviews with customer info
create or replace view product_reviews as
select
  r.id,
  r.product_id,
  r.rating,
  r.title,
  r.content,
  r.helpful_count,
  r.unhelpful_count,
  r.verified_purchase,
  c.name as reviewer_name,
  r.created_at,
  r.updated_at
from reviews r
join customers c on r.customer_id = c.id
order by r.created_at desc;

grant select on product_reviews to public;

-- Create view for product ratings summary
create or replace view product_ratings_summary as
select
  p.id as product_id,
  p.name,
  count(r.id) as review_count,
  round(avg(r.rating), 2) as average_rating,
  sum(case when r.rating = 5 then 1 else 0 end) as five_star_count,
  sum(case when r.rating = 4 then 1 else 0 end) as four_star_count,
  sum(case when r.rating = 3 then 1 else 0 end) as three_star_count,
  sum(case when r.rating = 2 then 1 else 0 end) as two_star_count,
  sum(case when r.rating = 1 then 1 else 0 end) as one_star_count
from products p
left join reviews r on p.id = r.product_id
group by p.id, p.name;

grant select on product_ratings_summary to public;

-- Create view for verified reviews only
create or replace view verified_product_reviews as
select
  r.id,
  r.product_id,
  r.rating,
  r.title,
  r.content,
  r.helpful_count,
  r.unhelpful_count,
  c.name as reviewer_name,
  r.created_at
from reviews r
join customers c on r.customer_id = c.id
where r.verified_purchase = true
order by r.helpful_count desc, r.created_at desc;

grant select on verified_product_reviews to public;

-- Create view for user's own reviews
create or replace view my_reviews as
select
  r.id,
  r.product_id,
  p.name as product_name,
  r.rating,
  r.title,
  r.content,
  r.helpful_count,
  r.unhelpful_count,
  r.verified_purchase,
  r.created_at,
  r.updated_at
from reviews r
join products p on r.product_id = p.id
where r.user_id = auth.uid();

grant select on my_reviews to authenticated;
