-- Drop existing trigger and function to recreate them
DROP TRIGGER IF EXISTS accept_invitations_on_signup ON auth.users;
DROP FUNCTION IF EXISTS accept_pending_invitations();

-- Recreate function with better error handling and case-insensitive email matching
CREATE OR REPLACE FUNCTION accept_pending_invitations()
RETURNS TRIGGER AS $$
DECLARE
  invitation_record RECORD;
  user_email TEXT;
BEGIN
  -- Get the user's email in lowercase for comparison
  user_email := LOWER(NEW.email);

  -- Find and process all pending invitations for this email
  FOR invitation_record IN
    SELECT * FROM team_invitations
    WHERE LOWER(invited_email) = user_email AND status = 'pending'
  LOOP
    BEGIN
      -- Create team member entry if it doesn't exist
      INSERT INTO team_members (team_id, user_id, role)
      VALUES (invitation_record.team_id, NEW.id, invitation_record.role)
      ON CONFLICT (team_id, user_id) DO UPDATE
      SET role = EXCLUDED.role;

      -- Mark invitation as accepted
      UPDATE team_invitations
      SET status = 'accepted', accepted_at = now()
      WHERE id = invitation_record.id;
    EXCEPTION WHEN OTHERS THEN
      -- Log error but don't fail the signup
      RAISE WARNING 'Error accepting invitation %: %', invitation_record.id, SQLERRM;
    END;
  END LOOP;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Recreate trigger
CREATE TRIGGER accept_invitations_on_signup
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION accept_pending_invitations();

-- Also update the invitations table to store emails in lowercase for consistency
CREATE OR REPLACE FUNCTION normalize_invitation_email()
RETURNS TRIGGER AS $$
BEGIN
  NEW.invited_email := LOWER(TRIM(NEW.invited_email));
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS normalize_invitation_email_trigger ON team_invitations;
CREATE TRIGGER normalize_invitation_email_trigger
BEFORE INSERT OR UPDATE ON team_invitations
FOR EACH ROW
EXECUTE FUNCTION normalize_invitation_email();
