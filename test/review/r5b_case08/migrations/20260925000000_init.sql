-- Create profiles table for user metadata
create table profiles (
  id uuid primary key references auth.users on delete cascade,
  username text unique,
  created_at timestamp with time zone default now()
);

-- Create recipes table
create table recipes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  title text not null,
  description text,
  ingredients text,
  instructions text not null,
  is_published boolean default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create index for faster queries
create index recipes_user_id_idx on recipes(user_id);
create index recipes_is_published_idx on recipes(is_published);

-- Enable Row Level Security
alter table profiles enable row level security;
alter table recipes enable row level security;

-- Profiles policies
create policy "Users can view their own profile"
  on profiles for select
  using (auth.uid() = id);

create policy "Users can update their own profile"
  on profiles for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

create policy "Users can insert their own profile"
  on profiles for insert
  with check (auth.uid() = id);

-- Recipes policies
-- Authenticated users can see their own recipes and all published recipes
create policy "recipes_select"
  on recipes for select
  to authenticated
  using (auth.uid() = user_id or is_published = true);

create policy "recipes_insert"
  on recipes for insert
  to authenticated
  with check (auth.uid() = user_id);

create policy "recipes_update"
  on recipes for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "recipes_delete"
  on recipes for delete
  to authenticated
  using (auth.uid() = user_id);

-- Create function to update the updated_at timestamp
create or replace function update_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

-- Create trigger for recipes updated_at
create trigger recipes_updated_at
  before update on recipes
  for each row
  execute function update_updated_at();
