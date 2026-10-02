-- Teams table
create table teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Team members with roles
create table team_members (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text default 'member' check (role in ('owner', 'admin', 'member')),
  joined_at timestamp with time zone default now(),
  unique(team_id, user_id)
);

-- Projects table
create table projects (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references teams(id) on delete cascade,
  name text not null,
  description text,
  status text default 'active' check (status in ('active', 'archived', 'completed')),
  created_by uuid not null references auth.users(id),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Tasks table
create table tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references projects(id) on delete cascade,
  title text not null,
  description text,
  status text default 'todo' check (status in ('todo', 'in_progress', 'done', 'cancelled')),
  priority text default 'medium' check (priority in ('low', 'medium', 'high', 'urgent')),
  assigned_to uuid references auth.users(id) on delete set null,
  due_date date,
  created_by uuid not null references auth.users(id),
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Task comments
create table task_comments (
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references tasks(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  content text not null,
  created_at timestamp with time zone default now(),
  updated_at timestamp with time zone default now()
);

-- Enable RLS
alter table teams enable row level security;
alter table team_members enable row level security;
alter table projects enable row level security;
alter table tasks enable row level security;
alter table task_comments enable row level security;

-- Teams: Users can see teams they're members of or own
create policy "users_can_view_own_teams" on teams
  for select using (
    owner_id = auth.uid() or
    id in (select team_id from team_members where user_id = auth.uid())
  );

create policy "users_can_create_teams" on teams
  for insert with check (owner_id = auth.uid());

create policy "team_owners_can_update" on teams
  for update using (owner_id = auth.uid());

create policy "team_owners_can_delete" on teams
  for delete using (owner_id = auth.uid());

-- Team members
create policy "team_members_can_view" on team_members
  for select using (
    user_id = auth.uid() or
    team_id in (select id from teams where owner_id = auth.uid()) or
    team_id in (select team_id from team_members where user_id = auth.uid())
  );

create policy "team_owners_can_manage_members" on team_members
  for insert with check (
    team_id in (select id from teams where owner_id = auth.uid())
  );

create policy "team_owners_can_update_members" on team_members
  for update using (
    team_id in (select id from teams where owner_id = auth.uid())
  );

create policy "team_owners_can_remove_members" on team_members
  for delete using (
    team_id in (select id from teams where owner_id = auth.uid())
  );

-- Projects: Accessible to team members
create policy "team_members_can_view_projects" on projects
  for select using (
    team_id in (
      select team_id from team_members where user_id = auth.uid()
      union
      select id from teams where owner_id = auth.uid()
    )
  );

create policy "team_members_can_create_projects" on projects
  for insert with check (
    team_id in (
      select team_id from team_members where user_id = auth.uid()
      union
      select id from teams where owner_id = auth.uid()
    )
  );

create policy "can_update_own_projects" on projects
  for update using (
    team_id in (
      select team_id from team_members where user_id = auth.uid()
      union
      select id from teams where owner_id = auth.uid()
    )
  );

-- Tasks: Accessible to team members
create policy "team_members_can_view_tasks" on tasks
  for select using (
    project_id in (
      select id from projects where team_id in (
        select team_id from team_members where user_id = auth.uid()
        union
        select id from teams where owner_id = auth.uid()
      )
    )
  );

create policy "team_members_can_create_tasks" on tasks
  for insert with check (
    project_id in (
      select id from projects where team_id in (
        select team_id from team_members where user_id = auth.uid()
        union
        select id from teams where owner_id = auth.uid()
      )
    )
  );

create policy "can_update_tasks" on tasks
  for update using (
    project_id in (
      select id from projects where team_id in (
        select team_id from team_members where user_id = auth.uid()
        union
        select id from teams where owner_id = auth.uid()
      )
    )
  );

-- Task comments
create policy "team_members_can_view_comments" on task_comments
  for select using (
    task_id in (
      select id from tasks where project_id in (
        select id from projects where team_id in (
          select team_id from team_members where user_id = auth.uid()
          union
          select id from teams where owner_id = auth.uid()
        )
      )
    )
  );

create policy "team_members_can_add_comments" on task_comments
  for insert with check (
    user_id = auth.uid() and
    task_id in (
      select id from tasks where project_id in (
        select id from projects where team_id in (
          select team_id from team_members where user_id = auth.uid()
          union
          select id from teams where owner_id = auth.uid()
        )
      )
    )
  );

-- Indexes for performance
create index idx_team_members_user on team_members(user_id);
create index idx_team_members_team on team_members(team_id);
create index idx_projects_team on projects(team_id);
create index idx_tasks_project on tasks(project_id);
create index idx_tasks_assigned on tasks(assigned_to);
create index idx_task_comments_task on task_comments(task_id);
