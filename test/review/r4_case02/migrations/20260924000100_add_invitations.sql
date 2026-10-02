-- Create team invitations table
CREATE TABLE team_invitations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  invited_email TEXT NOT NULL,
  invited_by UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  accepted_at TIMESTAMP WITH TIME ZONE,
  UNIQUE(team_id, invited_email)
);

-- Create index for lookups
CREATE INDEX idx_team_invitations_team_id ON team_invitations(team_id);
CREATE INDEX idx_team_invitations_invited_email ON team_invitations(invited_email);
CREATE INDEX idx_team_invitations_status ON team_invitations(status);

-- Enable RLS
ALTER TABLE team_invitations ENABLE ROW LEVEL SECURITY;

-- Team owners/admins can view invitations for their teams
CREATE POLICY "Team members can view invitations"
  ON team_invitations FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM team_members
      WHERE team_members.team_id = team_invitations.team_id AND team_members.user_id = auth.uid()
    ) OR
    EXISTS (SELECT 1 FROM teams WHERE teams.id = team_invitations.team_id AND teams.owner_id = auth.uid())
  );

-- Team owners/admins can create invitations
CREATE POLICY "Team owners can create invitations"
  ON team_invitations FOR INSERT
  WITH CHECK (
    invited_by = auth.uid() AND
    EXISTS (SELECT 1 FROM teams WHERE teams.id = team_invitations.team_id AND teams.owner_id = auth.uid())
  );

-- Users can accept their own invitations
CREATE POLICY "Users can accept their invitations"
  ON team_invitations FOR UPDATE
  USING (invited_email = auth.jwt() ->> 'email' AND status = 'pending')
  WITH CHECK (invited_email = auth.jwt() ->> 'email' AND status = 'accepted');

-- Owners can delete invitations
CREATE POLICY "Team owners can delete invitations"
  ON team_invitations FOR DELETE
  USING (
    EXISTS (SELECT 1 FROM teams WHERE teams.id = team_invitations.team_id AND teams.owner_id = auth.uid())
  );

-- Create function to auto-accept invitations for new users
CREATE OR REPLACE FUNCTION accept_pending_invitations()
RETURNS TRIGGER AS $$
DECLARE
  invitation_record RECORD;
BEGIN
  FOR invitation_record IN
    SELECT * FROM team_invitations
    WHERE invited_email = NEW.email AND status = 'pending'
  LOOP
    -- Create team member entry
    INSERT INTO team_members (team_id, user_id, role)
    VALUES (invitation_record.team_id, NEW.id, invitation_record.role)
    ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role;

    -- Mark invitation as accepted
    UPDATE team_invitations
    SET status = 'accepted', accepted_at = now()
    WHERE id = invitation_record.id;
  END LOOP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to auto-accept invitations when user signs up
CREATE TRIGGER accept_invitations_on_signup
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION accept_pending_invitations();
