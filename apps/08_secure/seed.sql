insert into public.notes (user_id, body) values ('{{A}}', 'alice private note'), ('{{B}}', 'bob private note');
insert into public.orgs (id, name) values ('{{ORG_A}}', 'Acme'), ('{{ORG_B}}', 'Beta');
insert into public.memberships (user_id, org_id) values ('{{A}}', '{{ORG_A}}'), ('{{B}}', '{{ORG_B}}');
insert into public.projects (org_id, name) values ('{{ORG_A}}', 'acme roadmap'), ('{{ORG_B}}', 'beta roadmap');
insert into storage.objects (bucket_id, name, owner) values ('uploads', 'alice/passport.jpg', '{{A}}'), ('uploads', 'bob/cv.pdf', '{{B}}');
