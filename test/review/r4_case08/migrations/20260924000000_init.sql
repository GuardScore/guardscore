-- Create recipes table
create table recipes (
  id bigint primary key generated always as identity,
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  description text,
  ingredients text not null,
  instructions text not null,
  published boolean not null default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Enable RLS
alter table recipes enable row level security;

-- Policy: Users can view their own recipes
create policy "recipes_select_own"
  on recipes
  for select
  to authenticated
  using (user_id = auth.uid());

-- Policy: Users can insert their own recipes
create policy "recipes_insert_own"
  on recipes
  for insert
  to authenticated
  with check (user_id = auth.uid());

-- Policy: Users can update their own recipes
create policy "recipes_update_own"
  on recipes
  for update
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- Policy: Users can delete their own recipes
create policy "recipes_delete_own"
  on recipes
  for delete
  to authenticated
  using (user_id = auth.uid());

-- Create index on user_id for faster queries
create index idx_recipes_user_id on recipes(user_id);

-- Create index on published for faster public recipe queries
create index idx_recipes_published on recipes(published);
