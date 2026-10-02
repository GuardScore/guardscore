-- Create users profiles table
create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  username text unique not null,
  full_name text,
  avatar_url text,
  bio text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

alter table public.profiles enable row level security;

-- Create recipes table
create table public.recipes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles on delete cascade,
  title text not null,
  description text,
  ingredients text[] not null default '{}',
  instructions text not null,
  prep_time_minutes integer,
  cook_time_minutes integer,
  servings integer default 4,
  difficulty text check (difficulty in ('easy', 'medium', 'hard')),
  tags text[] default '{}',
  published boolean default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

alter table public.recipes enable row level security;
create index recipes_user_id on recipes(user_id);
create index recipes_published on recipes(published);
create index recipes_created_at on recipes(created_at desc);

-- Create recipe ratings table
create table public.recipe_ratings (
  id uuid primary key default gen_random_uuid(),
  recipe_id uuid not null references public.recipes on delete cascade,
  user_id uuid not null references public.profiles on delete cascade,
  rating integer not null check (rating >= 1 and rating <= 5),
  comment text,
  created_at timestamp with time zone default now(),
  unique(recipe_id, user_id)
);

alter table public.recipe_ratings enable row level security;

-- Row level security policies

-- Profiles: anyone can view, users can update their own
create policy "Profiles are viewable by everyone" on public.profiles for select using (true);
create policy "Users can update their own profile" on public.profiles for update using (auth.uid() = id);

-- Recipes: can view published recipes and own recipes, can create/update/delete own
create policy "Published recipes visible to all" on public.recipes for select using (
  published = true
  or user_id = auth.uid()
);
create policy "Users can create recipes" on public.recipes for insert with check (auth.uid() = user_id);
create policy "Users can update their own recipes" on public.recipes for update using (auth.uid() = user_id);
create policy "Users can delete their own recipes" on public.recipes for delete using (auth.uid() = user_id);

-- Recipe ratings: anyone can rate published recipes, can view all ratings
create policy "Anyone can view recipe ratings" on public.recipe_ratings for select using (true);
create policy "Users can rate recipes" on public.recipe_ratings for insert with check (
  auth.uid() = user_id
  and exists (select 1 from public.recipes where id = recipe_id)
);
create policy "Users can update their own ratings" on public.recipe_ratings for update using (auth.uid() = user_id);
create policy "Users can delete their own ratings" on public.recipe_ratings for delete using (auth.uid() = user_id);
