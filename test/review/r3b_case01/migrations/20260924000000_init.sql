-- Create profiles table for user information
create table if not exists public.profiles (
  id uuid references auth.users(id) on delete cascade primary key,
  username text unique,
  avatar_url text,
  created_at timestamp with time zone default timezone('utc'::text, now()),
  updated_at timestamp with time zone default timezone('utc'::text, now())
);

-- Create recipes table
create table if not exists public.recipes (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  title text not null,
  description text,
  ingredients jsonb not null default '[]'::jsonb,
  instructions text not null,
  prep_time_minutes integer,
  cook_time_minutes integer,
  servings integer,
  image_url text,
  published boolean default false,
  created_at timestamp with time zone default timezone('utc'::text, now()),
  updated_at timestamp with time zone default timezone('utc'::text, now())
);

-- Create recipe likes/saves table
create table if not exists public.recipe_saves (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  recipe_id uuid references public.recipes(id) on delete cascade not null,
  created_at timestamp with time zone default timezone('utc'::text, now()),
  unique(user_id, recipe_id)
);

-- Create indexes for better query performance
create index idx_recipes_user_id on public.recipes(user_id);
create index idx_recipes_published on public.recipes(published);
create index idx_recipe_saves_user_id on public.recipe_saves(user_id);
create index idx_recipe_saves_recipe_id on public.recipe_saves(recipe_id);

-- Enable RLS
alter table public.profiles enable row level security;
alter table public.recipes enable row level security;
alter table public.recipe_saves enable row level security;

-- RLS Policies for profiles
create policy "Profiles are viewable by everyone" on public.profiles
  for select using (true);

create policy "Users can update their own profile" on public.profiles
  for update using (auth.uid() = id)
  with check (auth.uid() = id);

create policy "Users can insert their own profile" on public.profiles
  for insert with check (auth.uid() = id);

-- RLS Policies for recipes
create policy "Published recipes are viewable by everyone" on public.recipes
  for select using (published = true or auth.uid() = user_id);

create policy "Users can insert their own recipes" on public.recipes
  for insert with check (auth.uid() = user_id);

create policy "Users can update their own recipes" on public.recipes
  for update using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own recipes" on public.recipes
  for delete using (auth.uid() = user_id);

-- RLS Policies for recipe_saves
create policy "Users can view their own saves" on public.recipe_saves
  for select using (auth.uid() = user_id);

create policy "Users can save recipes" on public.recipe_saves
  for insert with check (auth.uid() = user_id);

create policy "Users can delete their own saves" on public.recipe_saves
  for delete using (auth.uid() = user_id);

-- Create function to update updated_at timestamp
create or replace function public.update_updated_at_column()
returns trigger as $$
begin
  new.updated_at = timezone('utc'::text, now());
  return new;
end;
$$ language plpgsql;

-- Create triggers for updated_at
create trigger update_profiles_updated_at before update on public.profiles
  for each row execute function public.update_updated_at_column();

create trigger update_recipes_updated_at before update on public.recipes
  for each row execute function public.update_updated_at_column();
