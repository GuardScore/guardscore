-- Users table (uses Supabase auth)
-- Auth users are in auth.users, we just reference them

-- Recipes table
create table recipes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  description text,
  ingredients jsonb not null default '[]'::jsonb, -- array of {name, amount, unit}
  instructions text not null,
  prep_time_minutes integer,
  cook_time_minutes integer,
  servings integer,
  is_published boolean default false,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Indexes for common queries
create index recipes_user_id_idx on recipes(user_id);
create index recipes_is_published_idx on recipes(is_published);
create index recipes_created_at_idx on recipes(created_at desc);

-- Enable RLS
alter table recipes enable row level security;

-- RLS Policies
-- Users can see their own recipes
create policy "Users can view own recipes"
  on recipes for select
  using (auth.uid() = user_id);

-- Users can see published recipes from others
create policy "Anyone can view published recipes"
  on recipes for select
  using (is_published = true);

-- Users can insert their own recipes
create policy "Users can insert recipes"
  on recipes for insert
  with check (auth.uid() = user_id);

-- Users can update their own recipes
create policy "Users can update own recipes"
  on recipes for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Users can delete their own recipes
create policy "Users can delete own recipes"
  on recipes for delete
  using (auth.uid() = user_id);

-- Comments table for published recipes
create table comments (
  id uuid primary key default gen_random_uuid(),
  recipe_id uuid not null references recipes(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  content text not null,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null
);

create index comments_recipe_id_idx on comments(recipe_id);
create index comments_user_id_idx on comments(user_id);

alter table comments enable row level security;

create policy "Anyone can view comments on published recipes"
  on comments for select
  using (
    exists (
      select 1 from recipes
      where recipes.id = comments.recipe_id
      and recipes.is_published = true
    )
  );

create policy "Users can insert comments"
  on comments for insert
  with check (auth.uid() = user_id);

create policy "Users can delete own comments"
  on comments for delete
  using (auth.uid() = user_id);

-- Favorites table
create table favorites (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  recipe_id uuid not null references recipes(id) on delete cascade,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  unique(user_id, recipe_id)
);

create index favorites_user_id_idx on favorites(user_id);
create index favorites_recipe_id_idx on favorites(recipe_id);

alter table favorites enable row level security;

create policy "Users can view own favorites"
  on favorites for select
  using (auth.uid() = user_id);

create policy "Users can add favorites"
  on favorites for insert
  with check (auth.uid() = user_id);

create policy "Users can remove favorites"
  on favorites for delete
  using (auth.uid() = user_id);
