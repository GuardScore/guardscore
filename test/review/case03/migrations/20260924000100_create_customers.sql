-- Create customers table
create table customers (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  name text not null,
  email text not null,
  phone text,
  address text,
  city text,
  state text,
  postal_code text,
  country text,
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now()
);

-- Enable RLS
alter table customers enable row level security;

-- Users can read their own customer record
create policy "customers_are_readable_by_owner"
  on customers
  for select
  to authenticated
  using (auth.uid() = user_id);

-- Users can update their own customer record
create policy "customers_are_updatable_by_owner"
  on customers
  for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Users can create their own customer record
create policy "customers_are_insertable_by_user"
  on customers
  for insert
  to authenticated
  with check (auth.uid() = user_id);

-- Create index on user_id for lookups
create index customers_user_id_idx on customers(user_id);
