-- Create auth schema if it doesn't exist
create schema if not exists auth;

-- Enable required extensions
create extension if not exists "uuid-ossp";

-- Users (extends Supabase auth.users)
create table if not exists public.users (
  id uuid primary key references auth.users on delete cascade,
  email text not null,
  full_name text,
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
  address text,
  city text,
  state text,
  zip_code text,
  country text,
  notes text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(user_id, name)
);

-- Projects table
create table if not exists public.projects (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.users(id) on delete cascade,
  client_id uuid not null references public.clients(id) on delete restrict,
  name text not null,
  description text,
  status text not null default 'active' check (status in ('active', 'completed', 'on_hold', 'cancelled')),
  start_date date,
  end_date date,
  budget decimal(12, 2),
  rate_type text default 'fixed' check (rate_type in ('fixed', 'hourly')),
  hourly_rate decimal(12, 2),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Invoices table
create table if not exists public.invoices (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.users(id) on delete cascade,
  client_id uuid not null references public.clients(id) on delete restrict,
  project_id uuid references public.projects(id) on delete set null,
  invoice_number text not null,
  status text not null default 'draft' check (status in ('draft', 'sent', 'paid', 'overdue', 'cancelled')),
  issue_date date not null,
  due_date date not null,
  amount decimal(12, 2) not null,
  tax_amount decimal(12, 2) default 0,
  notes text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now(),
  unique(user_id, invoice_number)
);

-- Invoice items table
create table if not exists public.invoice_items (
  id uuid primary key default uuid_generate_v4(),
  invoice_id uuid not null references public.invoices(id) on delete cascade,
  description text not null,
  quantity decimal(10, 2) not null default 1,
  unit_price decimal(12, 2) not null,
  amount decimal(12, 2) not null,
  created_at timestamp with time zone default now()
);

-- Indexes for performance
create index if not exists idx_clients_user_id on public.clients(user_id);
create index if not exists idx_projects_user_id on public.projects(user_id);
create index if not exists idx_projects_client_id on public.projects(client_id);
create index if not exists idx_invoices_user_id on public.invoices(user_id);
create index if not exists idx_invoices_client_id on public.invoices(client_id);
create index if not exists idx_invoices_project_id on public.invoices(project_id);
create index if not exists idx_invoice_items_invoice_id on public.invoice_items(invoice_id);

-- Enable Row Level Security
alter table public.users enable row level security;
alter table public.clients enable row level security;
alter table public.projects enable row level security;
alter table public.invoices enable row level security;
alter table public.invoice_items enable row level security;

-- RLS Policies for users table
create policy "Users can view their own profile"
  on public.users for select
  using (auth.uid() = id);

create policy "Users can update their own profile"
  on public.users for update
  using (auth.uid() = id);

-- RLS Policies for clients table
create policy "Users can view their own clients"
  on public.clients for select
  using (auth.uid() = user_id);

create policy "Users can insert their own clients"
  on public.clients for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own clients"
  on public.clients for update
  using (auth.uid() = user_id);

create policy "Users can delete their own clients"
  on public.clients for delete
  using (auth.uid() = user_id);

-- RLS Policies for projects table
create policy "Users can view their own projects"
  on public.projects for select
  using (auth.uid() = user_id);

create policy "Users can insert their own projects"
  on public.projects for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own projects"
  on public.projects for update
  using (auth.uid() = user_id);

create policy "Users can delete their own projects"
  on public.projects for delete
  using (auth.uid() = user_id);

-- RLS Policies for invoices table
create policy "Users can view their own invoices"
  on public.invoices for select
  using (auth.uid() = user_id);

create policy "Users can insert their own invoices"
  on public.invoices for insert
  with check (auth.uid() = user_id);

create policy "Users can update their own invoices"
  on public.invoices for update
  using (auth.uid() = user_id);

create policy "Users can delete their own invoices"
  on public.invoices for delete
  using (auth.uid() = user_id);

-- RLS Policies for invoice_items table (transitively through invoices)
create policy "Users can view invoice items for their invoices"
  on public.invoice_items for select
  using (
    exists (
      select 1 from public.invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );

create policy "Users can insert invoice items for their invoices"
  on public.invoice_items for insert
  with check (
    exists (
      select 1 from public.invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );

create policy "Users can update invoice items for their invoices"
  on public.invoice_items for update
  using (
    exists (
      select 1 from public.invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );

create policy "Users can delete invoice items for their invoices"
  on public.invoice_items for delete
  using (
    exists (
      select 1 from public.invoices
      where invoices.id = invoice_items.invoice_id
      and invoices.user_id = auth.uid()
    )
  );
