-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Users table (extends Supabase auth.users)
create table if not exists public.users (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  full_name text,
  company_name text,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
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
  country text,
  zip_code text,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Projects table
create table if not exists public.projects (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.users(id) on delete cascade,
  client_id uuid not null references public.clients(id) on delete cascade,
  name text not null,
  description text,
  status text default 'active' check (status in ('active', 'completed', 'on-hold', 'cancelled')),
  start_date date,
  end_date date,
  budget decimal(12, 2),
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null
);

-- Invoices table
create table if not exists public.invoices (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.users(id) on delete cascade,
  project_id uuid references public.projects(id) on delete set null,
  client_id uuid not null references public.clients(id) on delete cascade,
  invoice_number text not null,
  amount decimal(12, 2) not null,
  tax_amount decimal(12, 2) default 0,
  total_amount decimal(12, 2) generated always as (amount + coalesce(tax_amount, 0)) stored,
  description text,
  status text default 'draft' check (status in ('draft', 'sent', 'paid', 'overdue', 'cancelled')),
  issued_date date not null,
  due_date date not null,
  paid_date date,
  notes text,
  created_at timestamp with time zone default timezone('utc'::text, now()) not null,
  updated_at timestamp with time zone default timezone('utc'::text, now()) not null,
  unique(user_id, invoice_number)
);

-- Create indexes for performance
create index if not exists idx_clients_user_id on public.clients(user_id);
create index if not exists idx_projects_user_id on public.projects(user_id);
create index if not exists idx_projects_client_id on public.projects(client_id);
create index if not exists idx_invoices_user_id on public.invoices(user_id);
create index if not exists idx_invoices_client_id on public.invoices(client_id);
create index if not exists idx_invoices_project_id on public.invoices(project_id);

-- Enable Row Level Security
alter table public.users enable row level security;
alter table public.clients enable row level security;
alter table public.projects enable row level security;
alter table public.invoices enable row level security;

-- RLS Policies
-- Users can only read their own profile
create policy "Users can read own profile" on public.users
  for select using (auth.uid() = id);

create policy "Users can update own profile" on public.users
  for update using (auth.uid() = id);

-- Clients: users can only access their own clients
create policy "Users can read own clients" on public.clients
  for select using (auth.uid() = user_id);

create policy "Users can insert own clients" on public.clients
  for insert with check (auth.uid() = user_id);

create policy "Users can update own clients" on public.clients
  for update using (auth.uid() = user_id);

create policy "Users can delete own clients" on public.clients
  for delete using (auth.uid() = user_id);

-- Projects: users can only access their own projects
create policy "Users can read own projects" on public.projects
  for select using (auth.uid() = user_id);

create policy "Users can insert own projects" on public.projects
  for insert with check (auth.uid() = user_id);

create policy "Users can update own projects" on public.projects
  for update using (auth.uid() = user_id);

create policy "Users can delete own projects" on public.projects
  for delete using (auth.uid() = user_id);

-- Invoices: users can only access their own invoices
create policy "Users can read own invoices" on public.invoices
  for select using (auth.uid() = user_id);

create policy "Users can insert own invoices" on public.invoices
  for insert with check (auth.uid() = user_id);

create policy "Users can update own invoices" on public.invoices
  for update using (auth.uid() = user_id);

create policy "Users can delete own invoices" on public.invoices
  for delete using (auth.uid() = user_id);
