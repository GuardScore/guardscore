-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Clients table
create table clients (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null,
  name text not null,
  email text,
  phone text,
  company text,
  notes text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Projects table
create table projects (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null,
  client_id uuid not null references clients(id) on delete cascade,
  name text not null,
  description text,
  status text default 'active' check (status in ('active', 'completed', 'on_hold', 'cancelled')),
  hourly_rate numeric(10, 2),
  start_date date,
  end_date date,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Invoices table
create table invoices (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null,
  project_id uuid not null references projects(id) on delete cascade,
  invoice_number text not null unique,
  amount numeric(12, 2) not null,
  description text,
  due_date date not null,
  status text default 'draft' check (status in ('draft', 'sent', 'paid', 'overdue')),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Indexes for performance
create index idx_clients_user_id on clients(user_id);
create index idx_projects_user_id on projects(user_id);
create index idx_projects_client_id on projects(client_id);
create index idx_invoices_user_id on invoices(user_id);
create index idx_invoices_project_id on invoices(project_id);
create index idx_invoices_status on invoices(status);

-- Row level security
alter table clients enable row level security;
alter table projects enable row level security;
alter table invoices enable row level security;

-- RLS Policies for clients
create policy "Users can see their own clients" on clients
  for select using (auth.uid() = user_id);
create policy "Users can create clients" on clients
  for insert with check (auth.uid() = user_id);
create policy "Users can update their own clients" on clients
  for update using (auth.uid() = user_id);
create policy "Users can delete their own clients" on clients
  for delete using (auth.uid() = user_id);

-- RLS Policies for projects
create policy "Users can see their own projects" on projects
  for select using (auth.uid() = user_id);
create policy "Users can create projects" on projects
  for insert with check (auth.uid() = user_id);
create policy "Users can update their own projects" on projects
  for update using (auth.uid() = user_id);
create policy "Users can delete their own projects" on projects
  for delete using (auth.uid() = user_id);

-- RLS Policies for invoices
create policy "Users can see their own invoices" on invoices
  for select using (auth.uid() = user_id);
create policy "Users can create invoices" on invoices
  for insert with check (auth.uid() = user_id);
create policy "Users can update their own invoices" on invoices
  for update using (auth.uid() = user_id);
create policy "Users can delete their own invoices" on invoices
  for delete using (auth.uid() = user_id);
