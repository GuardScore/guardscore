-- Add sharing fields to notes table
alter table public.notes add column is_shared boolean default false;
alter table public.notes add column share_token text unique;

-- Create index for efficient share token lookups
create index notes_share_token_idx on public.notes(share_token) where is_shared = true;

-- Create a public notes view for shared notes (no authentication required)
-- Allow anyone to view shared notes
create policy "Anyone can view shared notes"
  on public.notes
  for select
  using (is_shared = true);
