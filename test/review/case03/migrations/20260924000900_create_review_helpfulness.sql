-- Create review_helpfulness table to track user votes
create table review_helpfulness (
  id uuid primary key default gen_random_uuid(),
  review_id uuid not null references reviews(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  is_helpful boolean not null,
  created_at timestamp with time zone not null default now(),
  unique(review_id, user_id)
);

-- Enable RLS
alter table review_helpfulness enable row level security;

-- Users can read helpfulness votes
create policy "review_helpfulness_readable_by_all"
  on review_helpfulness
  for select
  to public
  using (true);

-- Users can add/update their own helpfulness votes
create policy "users_can_vote_on_review_helpfulness"
  on review_helpfulness
  for all
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Create indexes
create index review_helpfulness_review_id_idx on review_helpfulness(review_id);
create index review_helpfulness_user_id_idx on review_helpfulness(user_id);
create index review_helpfulness_is_helpful_idx on review_helpfulness(is_helpful);

-- Create function to update review helpfulness counts
create or replace function update_review_helpfulness_counts()
returns trigger as $$
begin
  if new.is_helpful then
    update reviews
    set helpful_count = (
      select count(*) from review_helpfulness
      where review_id = new.review_id and is_helpful = true
    )
    where id = new.review_id;
  else
    update reviews
    set unhelpful_count = (
      select count(*) from review_helpfulness
      where review_id = new.review_id and is_helpful = false
    )
    where id = new.review_id;
  end if;
  return new;
end;
$$ language plpgsql;

-- Handle deletes
create or replace function update_review_helpfulness_on_delete()
returns trigger as $$
begin
  update reviews
  set
    helpful_count = (
      select count(*) from review_helpfulness
      where review_id = old.review_id and is_helpful = true
    ),
    unhelpful_count = (
      select count(*) from review_helpfulness
      where review_id = old.review_id and is_helpful = false
    )
  where id = old.review_id;
  return old;
end;
$$ language plpgsql;

-- Create triggers
create trigger update_review_helpfulness_on_insert_update
after insert or update on review_helpfulness
for each row
execute function update_review_helpfulness_counts();

create trigger update_review_helpfulness_on_delete
after delete on review_helpfulness
for each row
execute function update_review_helpfulness_on_delete();
