-- Enable necessary extensions
create extension if not exists "uuid-ossp";

-- Teams table
create table teams (
  id uuid primary key default uuid_generate_v4(),
  name text not null,
  description text,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Team members table (users in teams)
create table team_members (
  id uuid primary key default uuid_generate_v4(),
  team_id uuid not null references teams(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner', 'admin', 'member')),
  joined_at timestamp with time zone default now(),
  unique(team_id, user_id)
);

-- Projects table
create table projects (
  id uuid primary key default uuid_generate_v4(),
  team_id uuid not null references teams(id) on delete cascade,
  name text not null,
  description text,
  status text not null default 'active' check (status in ('active', 'archived', 'completed')),
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Tasks table
create table tasks (
  id uuid primary key default uuid_generate_v4(),
  project_id uuid not null references projects(id) on delete cascade,
  title text not null,
  description text,
  status text not null default 'todo' check (status in ('todo', 'in_progress', 'done')),
  priority text not null default 'medium' check (priority in ('low', 'medium', 'high')),
  assigned_to uuid references auth.users(id) on delete set null,
  created_by uuid not null references auth.users(id) on delete cascade,
  due_date date,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create indexes for better query performance
create index teams_created_by_idx on teams(created_by);
create index team_members_team_id_idx on team_members(team_id);
create index team_members_user_id_idx on team_members(user_id);
create index projects_team_id_idx on projects(team_id);
create index projects_created_by_idx on projects(created_by);
create index tasks_project_id_idx on tasks(project_id);
create index tasks_assigned_to_idx on tasks(assigned_to);
create index tasks_status_idx on tasks(status);
create index tasks_priority_idx on tasks(priority);

-- Enable RLS
alter table teams enable row level security;
alter table team_members enable row level security;
alter table projects enable row level security;
alter table tasks enable row level security;

-- RLS Policies for teams
create policy "Users can view teams they're members of"
  on teams for select
  using (
    auth.uid() = created_by or
    exists (
      select 1 from team_members
      where team_members.team_id = teams.id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Users can create teams"
  on teams for insert
  with check (auth.uid() = created_by);

create policy "Team owners can update their teams"
  on teams for update
  using (
    auth.uid() = created_by or
    exists (
      select 1 from team_members
      where team_members.team_id = teams.id
      and team_members.user_id = auth.uid()
      and team_members.role in ('owner', 'admin')
    )
  );

create policy "Team owners can delete their teams"
  on teams for delete
  using (auth.uid() = created_by);

-- RLS Policies for team_members
create policy "Users can view team members for teams they're in"
  on team_members for select
  using (
    auth.uid() in (
      select user_id from team_members tm
      where tm.team_id = team_members.team_id
    )
  );

create policy "Team owners can add members"
  on team_members for insert
  with check (
    exists (
      select 1 from team_members
      where team_members.team_id = team_members.team_id
      and team_members.user_id = auth.uid()
      and team_members.role in ('owner', 'admin')
    )
  );

create policy "Team owners can update members"
  on team_members for update
  using (
    exists (
      select 1 from team_members tm
      where tm.team_id = team_members.team_id
      and tm.user_id = auth.uid()
      and tm.role in ('owner', 'admin')
    )
  );

create policy "Team owners can remove members"
  on team_members for delete
  using (
    exists (
      select 1 from team_members tm
      where tm.team_id = team_members.team_id
      and tm.user_id = auth.uid()
      and tm.role in ('owner', 'admin')
    )
  );

-- RLS Policies for projects
create policy "Users can view projects in teams they're members of"
  on projects for select
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = projects.team_id
    ) or auth.uid() = created_by
  );

create policy "Team members can create projects"
  on projects for insert
  with check (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = projects.team_id
    )
  );

create policy "Team members can update projects in their team"
  on projects for update
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = projects.team_id
    )
  );

create policy "Team members can delete projects"
  on projects for delete
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = projects.team_id
    )
  );

-- RLS Policies for tasks
create policy "Users can view tasks in projects they have access to"
  on tasks for select
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = (
        select team_id from projects where projects.id = tasks.project_id
      )
    ) or auth.uid() = created_by
  );

create policy "Team members can create tasks"
  on tasks for insert
  with check (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = (
        select team_id from projects where projects.id = tasks.project_id
      )
    )
  );

create policy "Team members can update tasks"
  on tasks for update
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = (
        select team_id from projects where projects.id = tasks.project_id
      )
    )
  );

create policy "Team members can delete tasks"
  on tasks for delete
  using (
    auth.uid() in (
      select user_id from team_members
      where team_members.team_id = (
        select team_id from projects where projects.id = tasks.project_id
      )
    )
  );
