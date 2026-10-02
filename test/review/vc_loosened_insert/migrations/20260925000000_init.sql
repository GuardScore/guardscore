-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Create accounts table (one per freelancer)
create table accounts (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  business_name text,
  email text,
  phone text,
  address text,
  tax_id text,
  currency text default 'USD',
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create clients table
create table clients (
  id uuid primary key default uuid_generate_v4(),
  account_id uuid not null references accounts(id) on delete cascade,
  name text not null,
  email text,
  phone text,
  company text,
  address text,
  notes text,
  status text default 'active' check (status in ('active', 'inactive')),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create projects table
create table projects (
  id uuid primary key default uuid_generate_v4(),
  account_id uuid not null references accounts(id) on delete cascade,
  client_id uuid references clients(id) on delete set null,
  name text not null,
  description text,
  rate numeric(10, 2),
  rate_type text default 'hourly' check (rate_type in ('hourly', 'fixed')),
  status text default 'active' check (status in ('active', 'completed', 'paused')),
  start_date date,
  end_date date,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create invoices table
create table invoices (
  id uuid primary key default uuid_generate_v4(),
  account_id uuid not null references accounts(id) on delete cascade,
  project_id uuid references projects(id) on delete set null,
  client_id uuid not null references clients(id) on delete cascade,
  invoice_number text not null,
  status text default 'draft' check (status in ('draft', 'sent', 'paid', 'overdue', 'cancelled')),
  amount numeric(12, 2) not null,
  currency text default 'USD',
  issue_date date not null,
  due_date date not null,
  paid_date date,
  notes text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(account_id, invoice_number)
);

-- Create time entries table (for tracking hours)
create table time_entries (
  id uuid primary key default uuid_generate_v4(),
  account_id uuid not null references accounts(id) on delete cascade,
  project_id uuid not null references projects(id) on delete cascade,
  date date not null,
  hours numeric(5, 2) not null,
  description text,
  billable boolean default true,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create invoice line items table
create table invoice_items (
  id uuid primary key default uuid_generate_v4(),
  invoice_id uuid not null references invoices(id) on delete cascade,
  description text not null,
  quantity numeric(10, 2) not null default 1,
  rate numeric(10, 2) not null,
  amount numeric(12, 2) not null,
  created_at timestamp with time zone default now()
);

-- Create indexes for better query performance
create index idx_clients_account_id on clients(account_id);
create index idx_projects_account_id on projects(account_id);
create index idx_projects_client_id on projects(client_id);
create index idx_invoices_account_id on invoices(account_id);
create index idx_invoices_client_id on invoices(client_id);
create index idx_invoices_project_id on invoices(project_id);
create index idx_time_entries_account_id on time_entries(account_id);
create index idx_time_entries_project_id on time_entries(project_id);
create index idx_time_entries_date on time_entries(date);
create index idx_invoice_items_invoice_id on invoice_items(invoice_id);

-- Enable RLS for multi-tenancy
alter table accounts enable row level security;
alter table clients enable row level security;
alter table projects enable row level security;
alter table invoices enable row level security;
alter table time_entries enable row level security;
alter table invoice_items enable row level security;

-- RLS Policies for accounts - users can only see their own account
create policy "Users can view their own account"
  on accounts for select
  using (auth.uid() = user_id);

create policy "Users can update their own account"
  on accounts for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "Users can insert their own account"
  on accounts for insert
  with check (auth.uid() = user_id);

-- RLS Policies for clients - users can only see clients in their account
create policy "Users can view their clients"
  on clients for select
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can create clients"
  on clients for insert
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can update their clients"
  on clients for update
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ))
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can delete their clients"
  on clients for delete
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

-- RLS Policies for projects
create policy "Users can view their projects"
  on projects for select
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can create projects"
  on projects for insert
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can update their projects"
  on projects for update
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ))
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can delete their projects"
  on projects for delete
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

-- RLS Policies for invoices
create policy "Users can view their invoices"
  on invoices for select
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can create invoices"
  on invoices for insert
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can update their invoices"
  on invoices for update
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ))
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can delete their invoices"
  on invoices for delete
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

-- RLS Policies for time entries
create policy "Users can view their time entries"
  on time_entries for select
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can create time entries"
  on time_entries for insert
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can update their time entries"
  on time_entries for update
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ))
  with check (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

create policy "Users can delete their time entries"
  on time_entries for delete
  using (account_id in (
    select id from accounts where user_id = auth.uid()
  ));

-- RLS Policies for invoice items
create policy "Users can view invoice items"
  on invoice_items for select
  using (invoice_id in (
    select id from invoices
    where account_id in (
      select id from accounts where user_id = auth.uid()
    )
  ));

create policy "Users can create invoice items"
  on invoice_items for insert
  with check (invoice_id in (
    select id from invoices
    where account_id in (
      select id from accounts where user_id = auth.uid()
    )
  ));

create policy "Users can update invoice items"
  on invoice_items for update
  using (invoice_id in (
    select id from invoices
    where account_id in (
      select id from accounts where user_id = auth.uid()
    )
  ))
  with check (invoice_id in (
    select id from invoices
    where account_id in (
      select id from accounts where user_id = auth.uid()
    )
  ));

create policy "Users can delete invoice items"
  on invoice_items for delete
  using (invoice_id in (
    select id from invoices
    where account_id in (
      select id from accounts where user_id = auth.uid()
    )
  ));
