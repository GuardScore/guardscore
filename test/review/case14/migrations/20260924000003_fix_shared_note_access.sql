-- Add shared_by_email field to store who shared the note
alter table public.notes add column shared_by_email text;

-- Update the sharing policy to be more explicit
drop policy if exists "Anyone can view shared notes" on public.notes;

create policy "Anyone can view shared notes"
  on public.notes
  for select
  using (is_shared = true);
