insert into public.orgs (id, name) values ('{{ORG_A}}', 'Acme'), ('{{ORG_B}}', 'Beta');
insert into public.memberships (user_id, org_id) values ('{{A}}', '{{ORG_A}}'), ('{{B}}', '{{ORG_B}}');
insert into public.projects (org_id, name) values ('{{ORG_A}}', 'a'), ('{{ORG_B}}', 'b');
