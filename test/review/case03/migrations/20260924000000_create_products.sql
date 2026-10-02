-- Create products table
create table products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  price numeric(10, 2) not null check (price > 0),
  stock integer not null default 0 check (stock >= 0),
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now()
);

-- Enable RLS
alter table products enable row level security;

-- Public readable (everyone can see products)
create policy "products_are_readable_by_all"
  on products
  for select
  to public
  using (true);

-- Only authenticated users can insert/update/delete (admin-only in practice)
create policy "products_are_modifiable_by_authenticated"
  on products
  for all
  to authenticated
  using (auth.role() = 'authenticated')
  with check (auth.role() = 'authenticated');

-- Create index on created_at for sorting
create index products_created_at_idx on products(created_at desc);
