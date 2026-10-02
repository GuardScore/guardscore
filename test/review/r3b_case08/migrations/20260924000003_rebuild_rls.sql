-- Completely rebuild RLS for recipes table
alter table recipes disable row level security;
alter table recipes enable row level security;

-- Drop all existing policies
drop policy if exists "select_published" on recipes;
drop policy if exists "select_own" on recipes;
drop policy if exists "insert_own" on recipes;
drop policy if exists "update_own" on recipes;
drop policy if exists "delete_own" on recipes;
drop policy if exists "public_read_all" on recipes;

-- Policy 1: Anyone can read published recipes (no role specified = applies to all)
create policy "anyone_read_published" on recipes
  for select
  using (is_published = true);

-- Policy 2: Authenticated users can read their own recipes
create policy "auth_read_own" on recipes
  for select
  to authenticated
  using (auth.uid() = user_id);

-- Policy 3: Authenticated users can insert recipes
create policy "auth_insert" on recipes
  for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Policy 4: Authenticated users can update their own recipes
create policy "auth_update_own" on recipes
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Policy 5: Authenticated users can delete their own recipes
create policy "auth_delete_own" on recipes
  for delete
  to authenticated
  using (auth.uid() = user_id);
