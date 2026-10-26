-- TutorLink feedback: run once in Supabase (SQL Editor).
--
-- Testers can only ADD feedback. Nobody can read it through the public API,
-- except via admin_feedback(pw), which checks the admin password inside the
-- database. The password itself is never stored in the website files.

create extension if not exists pgcrypto with schema extensions;

-- 1. Feedback table
create table if not exists public.pilot_feedback (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  respondent_id uuid,
  role text not null check (role in ('Student', 'Tutor', 'Lecturer', 'Admin')),
  sus_score numeric(5,1) check (sus_score between 0 and 100),
  nps smallint check (nps between 0 and 10),
  nps_group text check (nps_group in ('promoter', 'passive', 'detractor')),
  disappointment text,
  time_saved text,
  answers jsonb not null check (pg_column_size(answers) < 20000)
);

alter table public.pilot_feedback enable row level security;

drop policy if exists "Testers can send feedback" on public.pilot_feedback;
create policy "Testers can send feedback"
  on public.pilot_feedback for insert
  to anon, authenticated
  with check (true);

-- Testers only ever need to insert.
revoke all on public.pilot_feedback from anon, authenticated;
grant insert on public.pilot_feedback to anon, authenticated;

-- 2. Admin password (stored only as a bcrypt hash, in a schema the API can't see)
create schema if not exists tutorlink_private;
revoke all on schema tutorlink_private from public, anon, authenticated;

create table if not exists tutorlink_private.admin_secret (
  id int primary key default 1 check (id = 1),
  pw_hash text not null
);

-- Set or change the password (run separately, replace the text in quotes):
--   insert into tutorlink_private.admin_secret (id, pw_hash)
--   values (1, extensions.crypt('YOUR-PASSWORD', extensions.gen_salt('bf', 10)))
--   on conflict (id) do update set pw_hash = excluded.pw_hash;

-- 3. Read everything, only with the right password
create or replace function public.admin_feedback(pw text)
returns setof public.pilot_feedback
language plpgsql
security definer
set search_path = ''
as $$
begin
  if pw is null or not exists (
    select 1 from tutorlink_private.admin_secret s
    where s.pw_hash = extensions.crypt(pw, s.pw_hash)
  ) then
    perform pg_sleep(1);  -- slows down password guessing
    raise exception 'wrong password' using errcode = '28000';
  end if;
  return query select * from public.pilot_feedback order by created_at;
end;
$$;

revoke all on function public.admin_feedback(text) from public;
grant execute on function public.admin_feedback(text) to anon, authenticated;

-- REMOVE EVERYTHING LATER (only TutorLink feedback; the rest of the project is untouched):
--   drop function if exists public.admin_feedback(text);
--   drop table if exists public.pilot_feedback;
--   drop schema if exists tutorlink_private cascade;
