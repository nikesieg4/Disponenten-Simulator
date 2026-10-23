-- ============================================================================
--  LEITSTELLE — Supabase-Setup (Login, Spielstände, Bann/Wartung/Flagging)
--  Supabase → SQL Editor → alles einfügen → RUN. Mehrfach ausführen ist ok.
-- ============================================================================
create extension if not exists pgcrypto;
set search_path = public, extensions;

create table if not exists app_users (
  id uuid primary key default gen_random_uuid(),
  username text unique not null, pass_hash text,
  auth_uid uuid unique, banned boolean not null default false,
  flagged boolean not null default false, flag_reason text, created_at timestamptz not null default now()
);
alter table app_users add column if not exists auth_uid uuid unique;
alter table app_users add column if not exists banned boolean not null default false;
alter table app_users add column if not exists flagged boolean not null default false;
alter table app_users add column if not exists flag_reason text;
alter table app_users alter column pass_hash drop not null;

-- Aufräumen: Administration und Shop/Zahlungen wurden entfernt (für bestehende Installationen)
delete from app_users where username='Administrator';
drop function if exists app_admin_search(uuid,text);
drop function if exists app_admin_add_credits(uuid,text,bigint);
drop function if exists app_admin_reset_pw(uuid,text,text);
drop function if exists app_admin_set_ban(uuid,text,boolean);
drop function if exists app_admin_clear_flag(uuid,text);
drop function if exists app_admin_delete_user(uuid,text);
drop function if exists app_admin_set_maintenance(uuid,boolean,text);
drop function if exists app_admin_reload(uuid);
drop function if exists app_admin_load_save(uuid,text);
drop function if exists app_admin_write_save(uuid,text,jsonb);
drop function if exists _is_admin(uuid);
drop function if exists shop_grant(uuid,bigint,text,text,int);
drop function if exists shop_uid(uuid);
drop table if exists shop_purchases;
drop table if exists shop_products;
alter table app_users drop column if exists is_admin;
alter table app_system drop column if exists reload_token;

create table if not exists app_saves ( user_id uuid primary key references app_users(id) on delete cascade, data jsonb, updated_at timestamptz not null default now() );
create table if not exists app_sessions ( token uuid primary key default gen_random_uuid(), user_id uuid not null references app_users(id) on delete cascade, created_at timestamptz not null default now() );
create table if not exists app_system ( id int primary key default 1, maintenance boolean not null default false, maintenance_text text );
insert into app_system(id) values (1) on conflict do nothing;
alter table app_system add column if not exists maintenance boolean not null default false;
alter table app_system add column if not exists maintenance_text text;

alter table app_users    enable row level security;
alter table app_saves    enable row level security;
alter table app_sessions enable row level security;
alter table app_system   enable row level security;
drop policy if exists app_system_read on app_system;
create policy app_system_read on app_system for select using (true);
revoke all on app_users, app_saves, app_sessions from anon, authenticated;
grant  select on app_system to anon, authenticated;

create or replace function _uid(p_token uuid) returns uuid language sql security definer set search_path=public, extensions as $$
  select user_id from app_sessions where token=p_token; $$;
create or replace function _maint() returns json language sql security definer set search_path=public, extensions as $$
  select json_build_object('maintenance',maintenance,'maintenance_text',coalesce(maintenance_text,'')) from app_system where id=1; $$;

create or replace function app_signup(p_username text, p_password text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_id uuid; v_token uuid; m json;
begin
  if length(coalesce(p_username,'')) < 3 then return json_build_object('error','Benutzername zu kurz (min. 3)'); end if;
  if length(coalesce(p_password,'')) < 4 then return json_build_object('error','Passwort zu kurz (min. 4)'); end if;
  if exists(select 1 from app_users where lower(username)=lower(p_username)) then return json_build_object('error','Benutzername bereits vergeben'); end if;
  insert into app_users(username, pass_hash) values (p_username, crypt(p_password, gen_salt('bf',10))) returning id into v_id;
  insert into app_saves(user_id, data) values (v_id, null);
  delete from app_sessions where user_id=v_id;
  insert into app_sessions(user_id) values (v_id) returning token into v_token;
  m := _maint();
  return json_build_object('token',v_token,'username',p_username,'maintenance',(m->>'maintenance')::boolean,'maintenance_text',m->>'maintenance_text');
end; $$;

create or replace function app_login(p_username text, p_password text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_user app_users; v_token uuid; m json;
begin
  select * into v_user from app_users where lower(username)=lower(p_username);
  if v_user.id is null or v_user.pass_hash is null or v_user.pass_hash <> crypt(p_password, v_user.pass_hash) then return json_build_object('error','Benutzername oder Passwort falsch'); end if;
  if v_user.banned then return json_build_object('error','Dieses Konto wurde gesperrt.'); end if;
  delete from app_sessions where user_id=v_user.id;
  insert into app_sessions(user_id) values (v_user.id) returning token into v_token;
  m := _maint();
  return json_build_object('token',v_token,'username',v_user.username,'maintenance',(m->>'maintenance')::boolean,'maintenance_text',m->>'maintenance_text');
end; $$;

create or replace function app_me(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_user app_users; m json;
begin
  select u.* into v_user from app_sessions s join app_users u on u.id=s.user_id where s.token=p_token;
  if v_user.id is null then return json_build_object('error','Sitzung ungültig'); end if;
  if v_user.banned then return json_build_object('error','Dieses Konto wurde gesperrt.'); end if;
  m := _maint();
  return json_build_object('username',v_user.username,'maintenance',(m->>'maintenance')::boolean,'maintenance_text',m->>'maintenance_text');
end; $$;

create or replace function app_logout(p_token uuid) returns void language sql security definer set search_path=public, extensions as $$ delete from app_sessions where token=p_token; $$;

create or replace function app_oauth_login()
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_auth uuid; v_email text; v_name text; v_user app_users; v_token uuid; v_uname text; m json;
begin
  v_auth := auth.uid(); if v_auth is null then return json_build_object('error','Nicht bei Google angemeldet'); end if;
  v_email := coalesce(auth.jwt()->>'email','');
  v_name  := coalesce(nullif(auth.jwt()->'user_metadata'->>'full_name',''), nullif(auth.jwt()->'user_metadata'->>'name',''), nullif(split_part(v_email,'@',1),''), 'Spieler');
  select * into v_user from app_users where auth_uid=v_auth;
  if v_user.id is null then
    v_uname := v_name;
    if exists(select 1 from app_users where lower(username)=lower(v_uname)) then v_uname := v_uname||'-'||substr(v_auth::text,1,4); end if;
    insert into app_users(username, auth_uid) values (v_uname, v_auth) returning * into v_user;
    insert into app_saves(user_id, data) values (v_user.id, null) on conflict (user_id) do nothing;
  end if;
  if v_user.banned then return json_build_object('error','Dieses Konto wurde gesperrt.'); end if;
  delete from app_sessions where user_id=v_user.id;
  insert into app_sessions(user_id) values (v_user.id) returning token into v_token;
  m := _maint();
  return json_build_object('token',v_token,'username',v_user.username,'maintenance',(m->>'maintenance')::boolean,'maintenance_text',m->>'maintenance_text');
end; $$;

create or replace function app_save(p_token uuid, p_data jsonb)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid; v_old bigint; v_oldt timestamptz; v_new bigint; v_dt numeric; v_delta bigint;
begin
  v_uid := _uid(p_token); if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  select (case when data->>'credits' ~ '^-?[0-9]+' then floor((data->>'credits')::numeric)::bigint else 0 end), updated_at into v_old, v_oldt from app_saves where user_id=v_uid;
  v_new := case when p_data->>'credits' ~ '^-?[0-9]+' then floor((p_data->>'credits')::numeric)::bigint else 0 end;
  insert into app_saves(user_id, data, updated_at) values (v_uid, p_data, now())
    on conflict (user_id) do update set data=excluded.data, updated_at=now();
  if v_old is not null then
    v_dt := greatest(1, extract(epoch from now()-v_oldt)); v_delta := v_new - coalesce(v_old,0);
    if v_delta > 3000000 and v_dt < 300 then
      update app_users set flagged=true, flag_reason='+'||to_char(v_delta,'FM999999999999')||' € in '||round(v_dt)||' s' where id=v_uid;
    end if;
  end if;
  return json_build_object('ok', true);
end; $$;

create or replace function app_load(p_token uuid)
returns jsonb language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid; v_data jsonb;
begin v_uid := _uid(p_token); if v_uid is null then return null; end if; select data into v_data from app_saves where user_id=v_uid; return v_data; end; $$;

create or replace function app_change_username(p_token uuid, p_new text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid;
begin
  v_uid := _uid(p_token); if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  if length(coalesce(p_new,''))<3 then return json_build_object('error','Benutzername zu kurz (min. 3)'); end if;
  if exists(select 1 from app_users where lower(username)=lower(p_new) and id<>v_uid) then return json_build_object('error','Benutzername bereits vergeben'); end if;
  update app_users set username=p_new where id=v_uid; return json_build_object('ok',true,'username',p_new);
end; $$;

create or replace function app_change_password(p_token uuid, p_new text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid;
begin
  v_uid := _uid(p_token); if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  if length(coalesce(p_new,''))<4 then return json_build_object('error','Passwort zu kurz (min. 4)'); end if;
  update app_users set pass_hash=crypt(p_new, gen_salt('bf',10)) where id=v_uid; return json_build_object('ok',true);
end; $$;

create or replace function app_delete_account(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid;
begin
  v_uid := _uid(p_token); if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  delete from app_users where id=v_uid; return json_build_object('ok',true);
end; $$;

grant execute on all functions in schema public to anon, authenticated;

notify pgrst, 'reload schema';
