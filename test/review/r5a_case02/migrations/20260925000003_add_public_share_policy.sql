-- Add policy to allow public access to shared notes via share token
create policy "Public can view shared notes"
  on notes
  for select
  using (exists (
    select 1 from shared_notes
    where shared_notes.note_id = notes.id
  ));
