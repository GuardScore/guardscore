-- Enable necessary extensions
create extension if not exists "uuid-ossp";

-- Create recipes table
create table recipes (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  description text,
  ingredients text[] not null default '{}',
  instructions text not null,
  prep_time_minutes integer,
  cook_time_minutes integer,
  servings integer,
  is_published boolean not null default false,
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now()
);

-- Create index for faster queries
create index recipes_user_id_idx on recipes(user_id);
create index recipes_is_published_idx on recipes(is_published);
create index recipes_created_at_idx on recipes(created_at desc);

-- Enable Row Level Security
alter table recipes enable row level security;

-- Policies for recipes
-- Users can view their own recipes
create policy "Users can view their own recipes"
  on recipes
  for select
  using (auth.uid() = user_id);

-- Anyone can view published recipes
create policy "Anyone can view published recipes"
  on recipes
  for select
  using (is_published = true);

-- Users can insert their own recipes
create policy "Users can insert their own recipes"
  on recipes
  for insert
  with check (auth.uid() = user_id);

-- Users can update their own recipes
create policy "Users can update their own recipes"
  on recipes
  for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Users can delete their own recipes
create policy "Users can delete their own recipes"
  on recipes
  for delete
  using (auth.uid() = user_id);
