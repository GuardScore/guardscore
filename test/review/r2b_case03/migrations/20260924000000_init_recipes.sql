-- Create recipes table
create table if not exists recipes (
  id uuid default gen_random_uuid() primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  description text,
  ingredients text not null,
  instructions text not null,
  is_published boolean default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Enable RLS
alter table recipes enable row level security;

-- Policy: Authenticated users can view their own recipes or any published recipes
create policy "recipes_select_auth" on recipes
  for select
  to authenticated
  using (
    auth.uid() = user_id or is_published = true
  );

-- Policy: Anonymous users can view published recipes
create policy "recipes_select_anon" on recipes
  for select
  to anon
  using (is_published = true);

-- Policy: Authenticated users can insert recipes only for themselves
create policy "recipes_insert" on recipes
  for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Policy: Authenticated users can update only their own recipes
create policy "recipes_update" on recipes
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Policy: Authenticated users can delete only their own recipes
create policy "recipes_delete" on recipes
  for delete
  to authenticated
  using (auth.uid() = user_id);

-- Create index for common queries
create index if not exists recipes_user_id_idx on recipes(user_id);
create index if not exists recipes_is_published_idx on recipes(is_published);
