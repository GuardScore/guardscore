-- Drop all existing policies
do $$ declare p record; begin
  for p in select policyname from pg_policies where schemaname = 'public' and tablename = 'recipes' loop
    execute format('drop policy %I on public.recipes', p.policyname);
  end loop;
end $$;

-- Single select policy that allows: owners see all their own recipes, anyone sees published recipes
create policy "recipes_select_policy" on recipes
  for select
  using (
    (auth.uid() = user_id) OR (is_published = true)
  );

-- Insert policy: authenticated users can only create their own recipes
create policy "recipes_insert_policy" on recipes
  for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Update policy: authenticated users can only update their own recipes
create policy "recipes_update_policy" on recipes
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Delete policy: authenticated users can only delete their own recipes
create policy "recipes_delete_policy" on recipes
  for delete
  to authenticated
  using (auth.uid() = user_id);
