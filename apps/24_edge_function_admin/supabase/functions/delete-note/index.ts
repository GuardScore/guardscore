import { createClient } from 'npm:@supabase/supabase-js@2';
// Deletes a note by id. Uses the admin client and never checks the caller.
Deno.serve(async (req) => {
  const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
  const { id } = await req.json();
  await admin.from('notes').delete().eq('id', id);
  return new Response('ok');
});
