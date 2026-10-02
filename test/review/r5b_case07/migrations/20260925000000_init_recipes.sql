-- Create recipes table
create table recipes (
  id bigint primary key generated always as identity,
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  description text,
  ingredients text not null,
  instructions text not null,
  is_published boolean not null default false,
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now()
);

-- Create index on user_id for faster queries
create index idx_recipes_user_id on recipes(user_id);
create index idx_recipes_is_published on recipes(is_published);

-- Enable RLS
alter table recipes enable row level security;

-- Policy: Users can see their own recipes (published or not)
create policy "Users can view their own recipes"
  on recipes for select
  using (auth.uid() = user_id);

-- Policy: Anyone can see published recipes
create policy "Anyone can view published recipes"
  on recipes for select
  using (is_published = true);

-- Policy: Users can insert their own recipes
create policy "Users can insert their own recipes"
  on recipes for insert
  with check (auth.uid() = user_id);

-- Policy: Users can update their own recipes
create policy "Users can update their own recipes"
  on recipes for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Policy: Users can delete their own recipes
create policy "Users can delete their own recipes"
  on recipes for delete
  using (auth.uid() = user_id);
