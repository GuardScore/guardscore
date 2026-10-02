-- Enable extensions
create extension if not exists "uuid-ossp";

-- Users table (extends auth.users)
create table if not exists public.users (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text,
  company_name text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Clients table
create table if not exists public.clients (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.users(id) on delete cascade,
  name text not null,
  email text,
  phone text,
  company text,
  address text,
  city text,
  state text,
  zip text,
  country text,
  notes text,
  status text default 'active' check (status in ('active', 'inactive', 'archived')),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(user_id, name)
);

-- Projects table
create table if not exists public.projects (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.users(id) on delete cascade,
  client_id uuid not null references public.clients(id) on delete cascade,
  name text not null,
  description text,
  status text default 'active' check (status in ('active', 'paused', 'completed', 'cancelled')),
  rate numeric(10, 2),
  rate_type text default 'hourly' check (rate_type in ('hourly', 'fixed', 'per_task')),
  start_date date,
  end_date date,
  notes text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Invoices table
create table if not exists public.invoices (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.users(id) on delete cascade,
  project_id uuid not null references public.projects(id) on delete cascade,
  client_id uuid not null references public.clients(id) on delete cascade,
  invoice_number text not null,
  status text default 'draft' check (status in ('draft', 'sent', 'paid', 'overdue', 'cancelled')),
  issue_date date not null,
  due_date date not null,
  amount numeric(12, 2) not null,
  paid_amount numeric(12, 2) default 0,
  description text,
  notes text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(user_id, invoice_number)
);

-- Invoice line items
create table if not exists public.invoice_items (
  id uuid primary key default uuid_generate_v4(),
  invoice_id uuid not null references public.invoices(id) on delete cascade,
  description text not null,
  quantity numeric(10, 2) default 1,
  rate numeric(10, 2) not null,
  amount numeric(12, 2) not null,
  created_at timestamp with time zone default now()
);

-- Time tracking (optional but useful for freelancers)
create table if not exists public.time_entries (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.users(id) on delete cascade,
  project_id uuid not null references public.projects(id) on delete cascade,
  description text,
  duration_minutes integer not null,
  date date not null,
  billable boolean default true,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create indexes for better query performance
create index if not exists clients_user_id_idx on public.clients(user_id);
create index if not exists projects_user_id_idx on public.projects(user_id);
create index if not exists projects_client_id_idx on public.projects(client_id);
create index if not exists invoices_user_id_idx on public.invoices(user_id);
create index if not exists invoices_client_id_idx on public.invoices(client_id);
create index if not exists invoices_project_id_idx on public.invoices(project_id);
create index if not exists invoices_status_idx on public.invoices(status);
create index if not exists time_entries_project_id_idx on public.time_entries(project_id);
create index if not exists time_entries_user_id_idx on public.time_entries(user_id);

-- Enable RLS
alter table public.users enable row level security;
alter table public.clients enable row level security;
alter table public.projects enable row level security;
alter table public.invoices enable row level security;
alter table public.invoice_items enable row level security;
alter table public.time_entries enable row level security;

-- RLS Policies - Users can only see their own profile
create policy "Users can view own profile" on public.users
  for select using (auth.uid() = id);

create policy "Users can update own profile" on public.users
  for update using (auth.uid() = id);

-- RLS Policies - Clients: users can only see their own clients
create policy "Users can view own clients" on public.clients
  for select using (auth.uid() = user_id);

create policy "Users can insert own clients" on public.clients
  for insert with check (auth.uid() = user_id);

create policy "Users can update own clients" on public.clients
  for update using (auth.uid() = user_id);

create policy "Users can delete own clients" on public.clients
  for delete using (auth.uid() = user_id);

-- RLS Policies - Projects: users can only see their own projects
create policy "Users can view own projects" on public.projects
  for select using (auth.uid() = user_id);

create policy "Users can insert own projects" on public.projects
  for insert with check (auth.uid() = user_id);

create policy "Users can update own projects" on public.projects
  for update using (auth.uid() = user_id);

create policy "Users can delete own projects" on public.projects
  for delete using (auth.uid() = user_id);

-- RLS Policies - Invoices: users can only see their own invoices
create policy "Users can view own invoices" on public.invoices
  for select using (auth.uid() = user_id);

create policy "Users can insert own invoices" on public.invoices
  for insert with check (auth.uid() = user_id);

create policy "Users can update own invoices" on public.invoices
  for update using (auth.uid() = user_id);

create policy "Users can delete own invoices" on public.invoices
  for delete using (auth.uid() = user_id);

-- RLS Policies - Invoice items: users can only see items in their invoices
create policy "Users can view own invoice items" on public.invoice_items
  for select using (
    exists (
      select 1 from public.invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );

create policy "Users can insert own invoice items" on public.invoice_items
  for insert with check (
    exists (
      select 1 from public.invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );

create policy "Users can update own invoice items" on public.invoice_items
  for update using (
    exists (
      select 1 from public.invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );

create policy "Users can delete own invoice items" on public.invoice_items
  for delete using (
    exists (
      select 1 from public.invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );

-- RLS Policies - Time entries: users can only see their own entries
create policy "Users can view own time entries" on public.time_entries
  for select using (auth.uid() = user_id);

create policy "Users can insert own time entries" on public.time_entries
  for insert with check (auth.uid() = user_id);

create policy "Users can update own time entries" on public.time_entries
  for update using (auth.uid() = user_id);

create policy "Users can delete own time entries" on public.time_entries
  for delete using (auth.uid() = user_id);
