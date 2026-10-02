-- Create profiles table for user metadata
create table if not exists public.profiles (
  id uuid references auth.users(id) on delete cascade primary key,
  email text,
  display_name text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create recipes table
create table if not exists public.recipes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  title text not null,
  description text,
  ingredients text not null,
  instructions text not null,
  is_published boolean default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create indexes for performance
create index if not exists idx_recipes_user_id on public.recipes(user_id);
create index if not exists idx_recipes_is_published on public.recipes(is_published);

-- Enable RLS
alter table public.profiles enable row level security;
alter table public.recipes enable row level security;

-- Profiles policies - only authenticated users can see their own profile
create policy "profiles_select_own" on public.profiles for select to authenticated
  using (auth.uid() = id);

create policy "profiles_insert_own" on public.profiles for insert to authenticated
  with check (auth.uid() = id);

create policy "profiles_update_own" on public.profiles for update to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

create policy "profiles_delete_own" on public.profiles for delete to authenticated
  using (auth.uid() = id);

-- Recipes policies
-- Allow anyone to read published recipes
create policy "recipes_select_published" on public.recipes for select
  using (is_published = true);

-- Allow authenticated users to read their own recipes (whether published or not)
create policy "recipes_select_own" on public.recipes for select to authenticated
  using (auth.uid() = user_id);

-- Allow authenticated users to create recipes
create policy "recipes_insert_own" on public.recipes for insert to authenticated
  with check (auth.uid() = user_id);

-- Allow authenticated users to update their own recipes
create policy "recipes_update_own" on public.recipes for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Allow authenticated users to delete their own recipes
create policy "recipes_delete_own" on public.recipes for delete to authenticated
  using (auth.uid() = user_id);
