-- Drop existing policies
drop policy if exists "Users can view their own recipes" on recipes;
drop policy if exists "Anyone can view published recipes" on recipes;
drop policy if exists "Users can insert their own recipes" on recipes;
drop policy if exists "Users can update their own recipes" on recipes;
drop policy if exists "Users can delete their own recipes" on recipes;

-- Create new policies that properly handle public and private recipes
-- Allow authenticated users to view their own recipes
create policy "Own recipes visible to owner"
  on recipes
  for select
  to authenticated
  using (auth.uid() = user_id);

-- Allow anyone to view published recipes
create policy "Published recipes visible to all"
  on recipes
  for select
  using (is_published = true);

-- Allow authenticated users to create their own recipes
create policy "Users can create own recipes"
  on recipes
  for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Allow authenticated users to update their own recipes
create policy "Users can update own recipes"
  on recipes
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Allow authenticated users to delete their own recipes
create policy "Users can delete own recipes"
  on recipes
  for delete
  to authenticated
  using (auth.uid() = user_id);
