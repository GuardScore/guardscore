-- Drop all existing policies on recipes
do $$ declare p record; begin
  for p in select policyname from pg_policies where schemaname = 'public' and tablename = 'recipes' loop
    execute format('drop policy %I on public.recipes', p.policyname);
  end loop;
end $$;

-- Policy 1: Authenticated users can see their own recipes
create policy "recipes_own_access" on recipes
  for select
  to authenticated
  using (auth.uid() = user_id);

-- Policy 2: Everyone (including anonymous) can see published recipes
create policy "recipes_public_access" on recipes
  for select
  to public
  using (is_published = true);

-- Policy 3: Authenticated users can create recipes
create policy "recipes_create" on recipes
  for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Policy 4: Authenticated users can update their own recipes
create policy "recipes_update" on recipes
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Policy 5: Authenticated users can delete their own recipes
create policy "recipes_delete" on recipes
  for delete
  to authenticated
  using (auth.uid() = user_id);
