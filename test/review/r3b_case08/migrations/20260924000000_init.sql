-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Create recipes table
create table recipes (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  description text,
  ingredients text[] not null default '{}',
  instructions text not null,
  is_published boolean not null default false,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create updated_at trigger
create or replace function update_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger recipes_updated_at
  before update on recipes
  for each row
  execute function update_updated_at();

-- Create indexes
create index recipes_user_id_idx on recipes(user_id);
create index recipes_is_published_idx on recipes(is_published);

-- Enable RLS
alter table recipes enable row level security;

-- RLS Policies
-- Published recipes are readable by anyone
create policy "Read published recipes" on recipes
  for select
  using (is_published = true);

-- Authenticated users can also read their own unpublished recipes
create policy "Users read own recipes" on recipes
  for select
  to authenticated
  using (auth.uid() = user_id);

-- Authenticated users can create recipes
create policy "Users create recipes" on recipes
  for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Authenticated users can update their own recipes
create policy "Users update own recipes" on recipes
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Authenticated users can delete their own recipes
create policy "Users delete own recipes" on recipes
  for delete
  to authenticated
  using (auth.uid() = user_id);
