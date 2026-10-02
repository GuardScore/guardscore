-- Create teams table
create table teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create team members table
create table team_members (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  user_id uuid not null,
  role text default 'member', -- 'admin', 'member'
  created_at timestamp with time zone default now(),
  unique(team_id, user_id)
);

-- Create projects table
create table projects (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  name text not null,
  description text,
  status text default 'active', -- 'active', 'archived', 'completed'
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create tasks table
create table tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references projects(id) on delete cascade,
  title text not null,
  description text,
  status text default 'todo', -- 'todo', 'in_progress', 'in_review', 'completed'
  priority text default 'medium', -- 'low', 'medium', 'high'
  assigned_to uuid,
  due_date timestamp with time zone,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create activity log table for tracking changes
create table activity_log (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  entity_type text not null, -- 'team', 'project', 'task'
  entity_id uuid not null,
  action text not null, -- 'created', 'updated', 'deleted'
  user_id uuid,
  changes jsonb,
  created_at timestamp with time zone default now()
);

-- Create indexes for better query performance
create index idx_team_members_team_id on team_members(team_id);
create index idx_team_members_user_id on team_members(user_id);
create index idx_projects_team_id on projects(team_id);
create index idx_tasks_project_id on tasks(project_id);
create index idx_tasks_assigned_to on tasks(assigned_to);
create index idx_activity_log_team_id on activity_log(team_id);
