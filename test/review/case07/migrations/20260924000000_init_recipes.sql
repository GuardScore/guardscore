-- Create recipes table
create table recipes (
  id bigint primary key generated always as identity,
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  ingredients text not null,
  instructions text not null,
  published boolean default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Enable RLS
alter table recipes enable row level security;

-- Policy: Users can view their own recipes
create policy "Users can view own recipes"
  on recipes for select
  using (auth.uid() = user_id);

-- Policy: Everyone can view published recipes
create policy "Everyone can view published recipes"
  on recipes for select
  using (published = true);

-- Policy: Users can insert their own recipes
create policy "Users can insert own recipes"
  on recipes for insert
  with check (auth.uid() = user_id);

-- Policy: Users can update their own recipes
create policy "Users can update own recipes"
  on recipes for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Policy: Users can delete their own recipes
create policy "Users can delete own recipes"
  on recipes for delete
  using (auth.uid() = user_id);

-- Create index for user_id lookups
create index recipes_user_id_idx on recipes(user_id);

-- Create index for published recipes lookups
create index recipes_published_idx on recipes(published);
