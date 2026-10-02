-- Create teams table
create table teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create team members table
create table team_members (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner', 'admin', 'member')),
  joined_at timestamp with time zone default now(),
  unique(team_id, user_id)
);

-- Create projects table
create table projects (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  team_id uuid not null references teams(id) on delete cascade,
  owner_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'active' check (status in ('active', 'archived', 'completed')),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Create tasks table
create table tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references projects(id) on delete cascade,
  title text not null,
  description text,
  status text not null default 'todo' check (status in ('todo', 'in_progress', 'done', 'blocked')),
  priority text not null default 'medium' check (priority in ('low', 'medium', 'high', 'urgent')),
  assignee_id uuid references auth.users(id) on delete set null,
  due_date date,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Add indexes for common queries
create index idx_teams_owner on teams(owner_id);
create index idx_team_members_user on team_members(user_id);
create index idx_team_members_team on team_members(team_id);
create index idx_projects_team on projects(team_id);
create index idx_projects_owner on projects(owner_id);
create index idx_tasks_project on tasks(project_id);
create index idx_tasks_assignee on tasks(assignee_id);
create index idx_tasks_creator on tasks(created_by);

-- Enable RLS
alter table teams enable row level security;
alter table team_members enable row level security;
alter table projects enable row level security;
alter table tasks enable row level security;

-- RLS Policies for teams
create policy "Users can see teams they belong to"
  on teams for select
  using (
    auth.uid() = owner_id or
    exists (
      select 1 from team_members
      where team_members.team_id = teams.id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Owners can insert teams"
  on teams for insert
  with check (auth.uid() = owner_id);

create policy "Owners can update their teams"
  on teams for update
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

create policy "Owners can delete their teams"
  on teams for delete
  using (auth.uid() = owner_id);

-- RLS Policies for team_members
create policy "Team members can see their team members"
  on team_members for select
  using (
    team_id in (
      select team_id from team_members where user_id = auth.uid()
    )
  );

create policy "Team owners can manage members"
  on team_members for insert
  with check (
    exists (
      select 1 from teams
      where teams.id = team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "Team owners can update members"
  on team_members for update
  using (
    exists (
      select 1 from teams
      where teams.id = team_id
      and teams.owner_id = auth.uid()
    )
  );

create policy "Team owners can delete members"
  on team_members for delete
  using (
    exists (
      select 1 from teams
      where teams.id = team_id
      and teams.owner_id = auth.uid()
    )
  );

-- RLS Policies for projects
create policy "Team members can see projects"
  on projects for select
  using (
    exists (
      select 1 from team_members
      where team_members.team_id = projects.team_id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Team members can create projects"
  on projects for insert
  with check (
    exists (
      select 1 from team_members
      where team_members.team_id = team_id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Project owners can update"
  on projects for update
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

create policy "Project owners can delete"
  on projects for delete
  using (auth.uid() = owner_id);

-- RLS Policies for tasks
create policy "Team members can see tasks in their projects"
  on tasks for select
  using (
    exists (
      select 1 from projects
      join team_members on team_members.team_id = projects.team_id
      where projects.id = tasks.project_id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Team members can create tasks"
  on tasks for insert
  with check (
    exists (
      select 1 from projects
      join team_members on team_members.team_id = projects.team_id
      where projects.id = project_id
      and team_members.user_id = auth.uid()
    )
  );

create policy "Users can update tasks they created or are assigned to"
  on tasks for update
  using (
    auth.uid() = created_by or
    auth.uid() = assignee_id or
    exists (
      select 1 from projects
      where projects.id = tasks.project_id
      and projects.owner_id = auth.uid()
    )
  );

create policy "Task creators can delete tasks"
  on tasks for delete
  using (auth.uid() = created_by);
