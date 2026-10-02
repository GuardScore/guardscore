-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Teams table
CREATE TABLE teams (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL,
  description TEXT,
  owner_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Team members
CREATE TABLE team_members (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT DEFAULT 'member', -- 'owner', 'admin', 'member'
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(team_id, user_id)
);

-- Projects table
CREATE TABLE projects (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  status TEXT DEFAULT 'active', -- 'active', 'archived'
  created_by UUID NOT NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Tasks table
CREATE TABLE tasks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT DEFAULT 'todo', -- 'todo', 'in_progress', 'done'
  priority TEXT DEFAULT 'medium', -- 'low', 'medium', 'high'
  assigned_to UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_by UUID NOT NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  due_date DATE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_teams_owner ON teams(owner_id);
CREATE INDEX idx_team_members_team ON team_members(team_id);
CREATE INDEX idx_team_members_user ON team_members(user_id);
CREATE INDEX idx_projects_team ON projects(team_id);
CREATE INDEX idx_projects_created_by ON projects(created_by);
CREATE INDEX idx_tasks_project ON tasks(project_id);
CREATE INDEX idx_tasks_assigned ON tasks(assigned_to);

-- RLS Policies

-- Teams: users can see teams they own or are members of
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_can_read_own_teams" ON teams
  FOR SELECT
  USING (
    owner_id = auth.uid()
    OR EXISTS (
      SELECT 1 FROM team_members
      WHERE team_members.team_id = teams.id
      AND team_members.user_id = auth.uid()
    )
  );

CREATE POLICY "users_can_create_teams" ON teams
  FOR INSERT
  WITH CHECK (owner_id = auth.uid());

CREATE POLICY "team_owners_can_update" ON teams
  FOR UPDATE
  USING (owner_id = auth.uid());

-- Team members: viewable by team members
ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;

CREATE POLICY "team_members_can_read" ON team_members
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM team_members tm
      WHERE tm.team_id = team_members.team_id
      AND tm.user_id = auth.uid()
    )
  );

CREATE POLICY "team_owners_can_manage" ON team_members
  FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM teams
      WHERE teams.id = team_members.team_id
      AND teams.owner_id = auth.uid()
    )
  );

CREATE POLICY "team_owners_can_remove" ON team_members
  FOR DELETE
  USING (
    EXISTS (
      SELECT 1 FROM teams
      WHERE teams.id = team_members.team_id
      AND teams.owner_id = auth.uid()
    )
  );

-- Projects: viewable by team members
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;

CREATE POLICY "team_members_can_read_projects" ON projects
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM team_members
      WHERE team_members.team_id = projects.team_id
      AND team_members.user_id = auth.uid()
    )
  );

CREATE POLICY "team_members_can_create_projects" ON projects
  FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM team_members
      WHERE team_members.team_id = projects.team_id
      AND team_members.user_id = auth.uid()
    )
  );

CREATE POLICY "team_members_can_update_projects" ON projects
  FOR UPDATE
  USING (
    EXISTS (
      SELECT 1 FROM team_members
      WHERE team_members.team_id = projects.team_id
      AND team_members.user_id = auth.uid()
    )
  );

-- Tasks: viewable by project team members
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;

CREATE POLICY "team_members_can_read_tasks" ON tasks
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM projects p
      JOIN team_members tm ON tm.team_id = p.team_id
      WHERE p.id = tasks.project_id
      AND tm.user_id = auth.uid()
    )
  );

CREATE POLICY "team_members_can_create_tasks" ON tasks
  FOR INSERT
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM projects p
      JOIN team_members tm ON tm.team_id = p.team_id
      WHERE p.id = tasks.project_id
      AND tm.user_id = auth.uid()
    )
  );

CREATE POLICY "team_members_can_update_tasks" ON tasks
  FOR UPDATE
  USING (
    EXISTS (
      SELECT 1 FROM projects p
      JOIN team_members tm ON tm.team_id = p.team_id
      WHERE p.id = tasks.project_id
      AND tm.user_id = auth.uid()
    )
  );
