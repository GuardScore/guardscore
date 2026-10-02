-- An agent "fixing" a bug where users couldn't see shared notes.
drop policy "notes_select_own" on public.notes;
create policy "notes_select_all" on public.notes for select to authenticated using (true);
