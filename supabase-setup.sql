-- AMBA.HUB community database setup
-- Run in Supabase SQL Editor. Enable email auth in Authentication settings.

create table if not exists public.public_scripts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 80),
  description text not null check (char_length(description) between 1 and 500),
  language text not null default 'text' check (language in ('lua','javascript','python','text')),
  code text not null check (char_length(code) between 1 and 100000),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now()
);

create index if not exists public_scripts_status_created_idx on public.public_scripts(status, created_at desc);
create index if not exists public_scripts_user_created_idx on public.public_scripts(user_id, created_at desc);
alter table public.public_scripts enable row level security;
revoke all on public.public_scripts from anon, authenticated;
grant select on public.public_scripts to anon, authenticated;
grant insert, delete on public.public_scripts to authenticated;

drop policy if exists "Anyone can read approved scripts or own submissions" on public.public_scripts;
create policy "Anyone can read approved scripts or own submissions"
  on public.public_scripts for select to anon, authenticated
  using (status = 'approved' or (select auth.uid()) = user_id);

drop policy if exists "Users submit their own pending scripts" on public.public_scripts;
create policy "Users submit their own pending scripts"
  on public.public_scripts for insert to authenticated
  with check ((select auth.uid()) = user_id and status = 'pending');

drop policy if exists "Users can delete their own submissions" on public.public_scripts;
create policy "Users can delete their own submissions"
  on public.public_scripts for delete to authenticated
  using ((select auth.uid()) = user_id and status = 'pending');

-- Official/admin scripts are a separate table. Only IDs listed in admin_users can manage it.
create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.admin_users enable row level security;
revoke all on public.admin_users from anon, authenticated;
grant select on public.admin_users to authenticated;
drop policy if exists "Users can view their own admin membership" on public.admin_users;
create policy "Users can view their own admin membership"
  on public.admin_users for select to authenticated
  using ((select auth.uid()) = user_id);
-- Secure helper checks admin membership without exposing the admin list to browsers.
create schema if not exists private;
create or replace function private.is_amba_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.admin_users au
    where au.user_id = (select auth.uid())
  );
$$;
revoke all on function private.is_amba_admin() from public;
grant usage on schema private to authenticated;
grant execute on function private.is_amba_admin() to authenticated;

create table if not exists public.admin_scripts (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 1 and 80),
  description text not null check (char_length(description) between 1 and 500),
  language text not null default 'text' check (language in ('lua','javascript','python','text')),
  code text not null check (char_length(code) between 1 and 100000),
  created_by uuid not null references auth.users(id),
  created_at timestamptz not null default now()
);
alter table public.admin_scripts enable row level security;
revoke all on public.admin_scripts from anon, authenticated;
grant select on public.admin_scripts to anon, authenticated;
grant insert, update, delete on public.admin_scripts to authenticated;

drop policy if exists "Anyone can read official scripts" on public.admin_scripts;
create policy "Anyone can read official scripts"
  on public.admin_scripts for select to anon, authenticated using (true);

drop policy if exists "Only admins can publish official scripts" on public.admin_scripts;
create policy "Only admins can publish official scripts"
  on public.admin_scripts for insert to authenticated
  with check (
    (select auth.uid()) = created_by and (select private.is_amba_admin())
  );

drop policy if exists "Only admins can update official scripts" on public.admin_scripts;
create policy "Only admins can update official scripts"
  on public.admin_scripts for update to authenticated
  using ((select private.is_amba_admin()))
  with check ((select private.is_amba_admin()));

drop policy if exists "Only admins can delete official scripts" on public.admin_scripts;
create policy "Only admins can delete official scripts"
  on public.admin_scripts for delete to authenticated
  using ((select private.is_amba_admin()));

-- After registering your account, find its UUID in Authentication > Users,
-- then add it as an admin using SQL Editor:
-- insert into public.admin_users (user_id) values ('YOUR-AUTH-USER-UUID');
-- To approve a community submission:
-- update public.public_scripts set status = 'approved' where id = 'SCRIPT-UUID';
