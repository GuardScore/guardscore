-- Add sharing fields to notes table
alter table notes
add column if not exists is_public boolean default false,
add column if not exists public_id text unique;

-- Create index for fast public_id lookups
create index if not exists idx_notes_public_id on notes(public_id) where is_public = true;

-- Function to generate a unique short ID
create or replace function generate_public_id()
returns text as $$
declare
  characters text := 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  result text := '';
  i int := 0;
begin
  for i in 1..12 loop
    result := result || substr(characters, floor(random() * 62)::int + 1, 1);
  end loop;
  return result;
end;
$$ language plpgsql;

-- Function to auto-generate public_id when a note becomes public
create or replace function handle_note_public()
returns trigger as $$
begin
  if new.is_public = true and new.public_id is null then
    new.public_id := generate_public_id();
  end if;
  return new;
end;
$$ language plpgsql;

-- Trigger to auto-generate public_id
drop trigger if exists on_note_public on notes;
create trigger on_note_public
  before insert or update on notes
  for each row
  execute procedure handle_note_public();

-- RLS policy: Anonymous users can read public notes
create policy "Anyone can read public notes" on notes
  for select
  using (is_public = true);
