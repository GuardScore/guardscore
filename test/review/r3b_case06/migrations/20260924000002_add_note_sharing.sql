-- Add sharing columns to notes table
alter table public.notes add column share_token text;
alter table public.notes add column shared_at timestamp with time zone;

-- Create unique index on share_token for efficient lookups
create unique index idx_notes_share_token on public.notes(share_token) where share_token is not null;

-- Allow public read access to shared notes via share_token
create policy "Public can view shared notes"
  on public.notes for select
  using (share_token is not null);
