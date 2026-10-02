-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Clients table
create table if not exists clients (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  email text,
  phone text,
  company text,
  address text,
  notes text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Projects table
create table if not exists projects (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  client_id uuid references clients(id) on delete set null,
  name text not null,
  description text,
  status text default 'active' check (status in ('active', 'completed', 'on-hold', 'cancelled')),
  rate_type text default 'hourly' check (rate_type in ('hourly', 'fixed', 'retainer')),
  rate numeric(10, 2),
  start_date date,
  end_date date,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Invoices table
create table if not exists invoices (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references auth.users(id) on delete cascade,
  client_id uuid not null references clients(id) on delete cascade,
  project_id uuid references projects(id) on delete set null,
  invoice_number text not null,
  status text default 'draft' check (status in ('draft', 'sent', 'paid', 'overdue', 'cancelled')),
  description text,
  amount numeric(12, 2) not null,
  tax_rate numeric(5, 2) default 0,
  tax_amount numeric(12, 2) default 0,
  total numeric(12, 2) generated always as (amount + tax_amount) stored,
  issue_date date not null,
  due_date date not null,
  paid_date date,
  notes text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Invoice items table for line items
create table if not exists invoice_items (
  id uuid primary key default uuid_generate_v4(),
  invoice_id uuid not null references invoices(id) on delete cascade,
  description text not null,
  quantity numeric(10, 2) default 1,
  unit_price numeric(12, 2) not null,
  amount numeric(12, 2) generated always as (quantity * unit_price) stored,
  created_at timestamp with time zone default now()
);

-- Create indexes
create index if not exists idx_clients_user_id on clients(user_id);
create index if not exists idx_projects_user_id on projects(user_id);
create index if not exists idx_projects_client_id on projects(client_id);
create index if not exists idx_invoices_user_id on invoices(user_id);
create index if not exists idx_invoices_client_id on invoices(client_id);
create index if not exists idx_invoices_project_id on invoices(project_id);
create index if not exists idx_invoice_items_invoice_id on invoice_items(invoice_id);

-- Row Level Security
alter table clients enable row level security;
alter table projects enable row level security;
alter table invoices enable row level security;
alter table invoice_items enable row level security;

-- RLS Policies for clients
create policy "Users can view their own clients"
  on clients for select
  using (auth.uid() = user_id);

create policy "Users can insert their own clients"
  on clients for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own clients"
  on clients for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own clients"
  on clients for delete
  using (auth.uid() = user_id);

-- RLS Policies for projects
create policy "Users can view their own projects"
  on projects for select
  using (auth.uid() = user_id);

create policy "Users can insert their own projects"
  on projects for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own projects"
  on projects for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own projects"
  on projects for delete
  using (auth.uid() = user_id);

-- RLS Policies for invoices
create policy "Users can view their own invoices"
  on invoices for select
  using (auth.uid() = user_id);

create policy "Users can insert their own invoices"
  on invoices for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own invoices"
  on invoices for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can delete their own invoices"
  on invoices for delete
  using (auth.uid() = user_id);

-- RLS Policies for invoice_items
create policy "Users can view invoice items for their invoices"
  on invoice_items for select
  using (
    exists (
      select 1 from invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );

create policy "Users can insert invoice items for their invoices"
  on invoice_items for insert
  with check (
    exists (
      select 1 from invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );

create policy "Users can update invoice items for their invoices"
  on invoice_items for update
  using (
    exists (
      select 1 from invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  )
  with check (
    exists (
      select 1 from invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );

create policy "Users can delete invoice items for their invoices"
  on invoice_items for delete
  using (
    exists (
      select 1 from invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );
