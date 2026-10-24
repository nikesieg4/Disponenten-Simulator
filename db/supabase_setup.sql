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
alter table if exists app_system drop column if exists reload_token;

create table if not exists app_saves ( user_id uuid primary key references app_users(id) on delete cascade, data jsonb, updated_at timestamptz not null default now() );
-- Sitzungen: nur der SHA-256-Hash des Tokens wird gespeichert, Ablauf nach 30 Tagen ohne Nutzung.
-- Alte Tabelle mit Klartext-Tokens ersetzen (alle Spieler melden sich einmal neu an).
do $$ begin
  if exists(select 1 from information_schema.columns where table_schema='public' and table_name='app_sessions' and column_name='token') then
    drop table app_sessions;
  end if;
end $$;
create table if not exists app_sessions ( token_hash text primary key, user_id uuid not null references app_users(id) on delete cascade,
  created_at timestamptz not null default now(), expires_at timestamptz not null default now() + interval '30 days' );
create index if not exists app_sessions_user on app_sessions(user_id);
-- Fehlversuche beim Login (je Benutzername und je IP-Adresse)
create table if not exists app_login_attempts ( key text primary key, fails int not null default 0, locked_until timestamptz, last_fail timestamptz not null default now() );
-- Anti-Cheat: Guthaben-Budget für Einnahmen und Zeitpunkt der letzten Prüfung
alter table app_saves add column if not exists earn_bucket numeric;
alter table app_saves add column if not exists checked_at timestamptz;
-- Preise für die Prüfung (Block unten wird aus index.html erzeugt)
create table if not exists app_prices ( kind text not null, id text not null, price bigint not null, primary key (kind, id) );
create table if not exists app_system ( id int primary key default 1, maintenance boolean not null default false, maintenance_text text );
insert into app_system(id) values (1) on conflict do nothing;
alter table app_system add column if not exists maintenance boolean not null default false;
alter table app_system add column if not exists maintenance_text text;

alter table app_users    enable row level security;
alter table app_saves    enable row level security;
alter table app_sessions enable row level security;
alter table app_system   enable row level security;
alter table app_login_attempts enable row level security;
alter table app_prices enable row level security;
drop policy if exists app_system_read on app_system;
create policy app_system_read on app_system for select using (true);
revoke all on app_users, app_saves, app_sessions, app_login_attempts, app_prices from anon, authenticated;
grant  select on app_system to anon, authenticated;

create or replace function _token_hash(p_token uuid) returns text language sql immutable set search_path=public, extensions as $$
  select encode(digest(p_token::text,'sha256'),'hex'); $$;
create or replace function _uid(p_token uuid) returns uuid language sql security definer set search_path=public, extensions as $$
  select user_id from app_sessions where token_hash=_token_hash(p_token) and expires_at > now(); $$;
-- Neue Sitzung: alte Sitzungen des Kontos und abgelaufene Sitzungen löschen, Token nur einmal im Klartext zurückgeben
create or replace function _new_session(p_uid uuid) returns uuid language plpgsql security definer set search_path=public, extensions as $$
declare v_token uuid := gen_random_uuid();
begin
  delete from app_sessions where user_id=p_uid or expires_at <= now();
  insert into app_sessions(token_hash, user_id) values (_token_hash(v_token), p_uid);
  return v_token;
end; $$;
-- Login-Sperre: 5 Fehlversuche je Benutzername bzw. 30 je IP → 15 Minuten gesperrt
create or replace function _client_ip() returns text language sql stable as $$
  select nullif(split_part(coalesce(current_setting('request.headers',true)::json->>'x-forwarded-for',''),',',1),''); $$;
create or replace function _login_locked(p_keys text[]) returns timestamptz language sql security definer set search_path=public, extensions as $$
  select max(locked_until) from app_login_attempts where key = any(p_keys) and locked_until > now(); $$;
create or replace function _login_fail(p_keys text[]) returns void language plpgsql security definer set search_path=public, extensions as $$
declare k text; v_fails int;
begin
  foreach k in array p_keys loop
    insert into app_login_attempts(key, fails, last_fail) values (k, 1, now())
      on conflict (key) do update set fails = case when app_login_attempts.last_fail < now() - interval '15 minutes' then 1 else app_login_attempts.fails + 1 end, last_fail = now()
      returning fails into v_fails;
    if v_fails >= (case when k like 'ip:%' then 30 else 5 end) then
      update app_login_attempts set locked_until = now() + interval '15 minutes', fails = 0 where key = k;
    end if;
  end loop;
  delete from app_login_attempts where last_fail < now() - interval '1 day' and (locked_until is null or locked_until < now());
end; $$;
create or replace function _maint() returns json language sql security definer set search_path=public, extensions as $$
  select json_build_object('maintenance',maintenance,'maintenance_text',coalesce(maintenance_text,'')) from app_system where id=1; $$;

create or replace function app_signup(p_username text, p_password text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_id uuid; v_token uuid; m json;
begin
  if length(coalesce(p_username,'')) < 3 then return json_build_object('error','Benutzername zu kurz (min. 3)'); end if;
  if length(coalesce(p_password,'')) < 8 then return json_build_object('error','Passwort zu kurz (min. 8 Zeichen)'); end if;
  if exists(select 1 from app_users where lower(username)=lower(p_username)) then return json_build_object('error','Benutzername bereits vergeben'); end if;
  insert into app_users(username, pass_hash) values (p_username, crypt(p_password, gen_salt('bf',10))) returning id into v_id;
  insert into app_saves(user_id, data) values (v_id, null);
  v_token := _new_session(v_id);
  m := _maint();
  return json_build_object('token',v_token,'username',p_username,'maintenance',(m->>'maintenance')::boolean,'maintenance_text',m->>'maintenance_text');
end; $$;

create or replace function app_login(p_username text, p_password text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_user app_users; v_token uuid; m json; v_keys text[]; v_until timestamptz; v_ip text;
begin
  v_keys := array['user:'||lower(coalesce(p_username,''))]; v_ip := _client_ip();
  if v_ip is not null then v_keys := v_keys || ('ip:'||v_ip); end if;
  v_until := _login_locked(v_keys);
  if v_until is not null then
    return json_build_object('error','Zu viele Fehlversuche. Bitte in '||greatest(1,ceil(extract(epoch from v_until-now())/60))::int||' Minuten erneut versuchen.');
  end if;
  select * into v_user from app_users where lower(username)=lower(p_username);
  if v_user.id is null or v_user.pass_hash is null or v_user.pass_hash <> crypt(p_password, v_user.pass_hash) then
    perform _login_fail(v_keys);
    return json_build_object('error','Benutzername oder Passwort falsch');
  end if;
  if v_user.banned then return json_build_object('error','Dieses Konto wurde gesperrt.'); end if;
  delete from app_login_attempts where key = 'user:'||lower(v_user.username);
  v_token := _new_session(v_user.id);
  m := _maint();
  return json_build_object('token',v_token,'username',v_user.username,'maintenance',(m->>'maintenance')::boolean,'maintenance_text',m->>'maintenance_text');
end; $$;

create or replace function app_me(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_user app_users; m json;
begin
  select u.* into v_user from app_sessions s join app_users u on u.id=s.user_id where s.token_hash=_token_hash(p_token) and s.expires_at > now();
  if v_user.id is null then return json_build_object('error','Sitzung ungültig'); end if;
  update app_sessions set expires_at = now() + interval '30 days' where token_hash=_token_hash(p_token);   -- aktive Spieler bleiben angemeldet
  if v_user.banned then return json_build_object('error','Dieses Konto wurde gesperrt.'); end if;
  m := _maint();
  return json_build_object('username',v_user.username,'maintenance',(m->>'maintenance')::boolean,'maintenance_text',m->>'maintenance_text');
end; $$;

create or replace function app_logout(p_token uuid) returns void language sql security definer set search_path=public, extensions as $$ delete from app_sessions where token_hash=_token_hash(p_token); $$;

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
  v_token := _new_session(v_user.id);
  m := _maint();
  return json_build_object('token',v_token,'username',v_user.username,'maintenance',(m->>'maintenance')::boolean,'maintenance_text',m->>'maintenance_text');
end; $$;

-- PREISE:BEGIN (automatisch erzeugt mit: node werkzeuge/preise_sql.cjs, nicht von Hand ändern)
delete from app_prices;
insert into app_prices(kind, id, price) values
  ('vehicle','hlf20',650000),
  ('vehicle','lf20',480000),
  ('vehicle','dlk',950000),
  ('vehicle','rw',700000),
  ('vehicle','elw1c',250000),
  ('vehicle','elw1b',260000),
  ('vehicle','lfkats',420000),
  ('vehicle','gw_g',650000),
  ('vehicle','gw_mess',450000),
  ('vehicle','gw_a',400000),
  ('vehicle','gw_dekonp',500000),
  ('vehicle','klef',150000),
  ('vehicle','tlf',580000),
  ('vehicle','elw2',900000),
  ('vehicle','fmew',300000),
  ('vehicle','lhf16',480000),
  ('vehicle','lf16ts',300000),
  ('vehicle','tlf1624',420000),
  ('vehicle','tlf2024',520000),
  ('vehicle','tlf3000',450000),
  ('vehicle','tlf4000',550000),
  ('vehicle','tlf2450cafs',620000),
  ('vehicle','sw2000',350000),
  ('vehicle','swkats',330000),
  ('vehicle','mtf',90000),
  ('vehicle','gw_hoehe',420000),
  ('vehicle','tm50',1500000),
  ('vehicle','fwk',1200000),
  ('vehicle','gw_taucher',380000),
  ('vehicle','gw_wr',320000),
  ('vehicle','mzb',120000),
  ('vehicle','wlf',300000),
  ('vehicle','ab_atemschutz',250000),
  ('vehicle','ab_auffang',150000),
  ('vehicle','ab_gefahrgut',300000),
  ('vehicle','ab_dekon',350000),
  ('vehicle','ab_schlauch',150000),
  ('vehicle','ab_lueft',250000),
  ('vehicle','ab_tank',200000),
  ('vehicle','ab_sonderl',300000),
  ('vehicle','ab_schaum',250000),
  ('vehicle','rtw',280000),
  ('vehicle','nef',150000),
  ('vehicle','ktw',120000),
  ('vehicle','itw',380000),
  ('vehicle','lkw1',150000),
  ('vehicle','lkw2',200000),
  ('vehicle','mtf3',200000),
  ('vehicle','fwa_notstrom',60000),
  ('vehicle','fwa_vent',45000),
  ('vehicle','gw_betreuung',250000),
  ('vehicle','fwa_fkh',40000),
  ('vehicle','stemo',1000000),
  ('vehicle','kdow_lna',120000),
  ('vehicle','nktw',150000),
  ('vehicle','gw_san',250000),
  ('vehicle','kdow',90000),
  ('vehicle','ab_manv',200000),
  ('vehicle','lhf10',480000),
  ('station','L1',5000000),
  ('station','L2',6350000),
  ('station','L3',7800000),
  ('station','L4',9200000),
  ('station','L5',11300000),
  ('station','L6',13750000),
  ('academy','L1',12000000),
  ('academy','L2',15000000),
  ('academy','L3',18500000),
  ('academy','L4',22500000),
  ('academy','L5',27000000),
  ('cfg','startCredits',8000000);
-- PREISE:END

/* ---------------------------------------------------------------------------
   Anti-Cheat beim Speichern
   Vermögen = Guthaben + Tageskasse + Mindestwert aller Fahrzeuge/Wachen/Akademien.
   Kaufen, Ausbauen und die Auszahlung der Tageskasse ändern das Vermögen nicht
   (Geld wird nur umgeschichtet). Steigen darf es nur durch Einnahmen, und die sind
   begrenzt: Ein Budget füllt sich je Fahrzeug mit 1 Mio. €/h (gedeckelt bei 12 h).
   Was darüber hinausgeht, wird abgezogen: zuerst von der Tageskasse, dann vom Guthaben.
   --------------------------------------------------------------------------- */
create or replace function _jnum(j jsonb, k text) returns numeric language sql immutable as $$
  select case when jsonb_typeof(j->k)='number' then (j->>k)::numeric else 0 end; $$;
create or replace function _jlevel(j jsonb, maxl int) returns int language sql immutable as $$
  select least(maxl, greatest(1, case when jsonb_typeof(j->'level')='number' then floor((j->>'level')::numeric)::int else 1 end)); $$;
create or replace function _jarr(j jsonb, k text) returns jsonb language sql immutable as $$
  select case when jsonb_typeof(j->k)='array' then j->k else '[]'::jsonb end; $$;
create or replace function _assets(d jsonb) returns numeric language sql stable security definer set search_path=public, extensions as $$
  select
    coalesce((select sum(p.price) from jsonb_array_elements(_jarr(d,'vehicles')) v join app_prices p on p.kind='vehicle' and p.id=v->>'type'),0)
  + coalesce((select sum(p.price) from jsonb_array_elements(_jarr(d,'stations')) st join app_prices p on p.kind='station' and p.id='L'||_jlevel(st,6)),0)
  + coalesce((select sum(p.price) from jsonb_array_elements(_jarr(d,'buildings')) b join app_prices p on p.kind='academy' and p.id='L'||_jlevel(b,5) where b->>'typeId'='academy'),0); $$;
create or replace function _vehicle_count(d jsonb) returns int language sql stable security definer set search_path=public, extensions as $$
  select count(*)::int from jsonb_array_elements(_jarr(d,'vehicles')) v join app_prices p on p.kind='vehicle' and p.id=v->>'type'; $$;

create or replace function app_save(p_token uuid, p_data jsonb)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare
  v_uid uuid; v_old jsonb; v_bucket numeric; v_at timestamptz;
  v_rate numeric; v_cap numeric; v_w_old numeric; v_w_new numeric; v_excess numeric;
  v_cr numeric; v_ea numeric; v_cut_e numeric := 0; v_cut_c numeric := 0;
  c_per_veh_h constant numeric := 1000000;   -- max. Einnahmen je Fahrzeug und Stunde
  c_cap_h     constant numeric := 12;        -- Budget reicht höchstens für 12 Stunden
begin
  v_uid := _uid(p_token); if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  if jsonb_typeof(p_data) is distinct from 'object' then return json_build_object('error','Ungültiger Spielstand'); end if;
  select data, earn_bucket, checked_at into v_old, v_bucket, v_at from app_saves where user_id=v_uid for update;

  -- Geldwerte normalisieren (nur Zahlen)
  v_cr := round(_jnum(p_data,'credits')); v_ea := greatest(0, round(_jnum(p_data,'earnings')));

  if v_old is null or jsonb_typeof(v_old) <> 'object' then
    v_w_old := (select price from app_prices where kind='cfg' and id='startCredits');   -- neues Konto
    v_bucket := 0; v_rate := 0;
  else
    v_w_old := _jnum(v_old,'credits') + greatest(0,_jnum(v_old,'earnings')) + _assets(v_old);
    v_rate := least(_vehicle_count(v_old), _vehicle_count(p_data)) * c_per_veh_h / 3600.0;   -- € je Sekunde
    v_cap := v_rate * c_cap_h * 3600;
    if v_bucket is null then v_bucket := v_cap; v_at := now(); end if;                     -- bestehende Spielstände: volles Budget
    v_bucket := least(v_cap, v_bucket + v_rate * greatest(0, extract(epoch from now() - coalesce(v_at, now()))));
  end if;

  v_w_new := v_cr + v_ea + _assets(p_data);
  v_excess := ceil(v_w_new - (v_w_old + floor(v_bucket)));   -- ganze Euro
  if v_excess > 0 then
    -- abgleichen: erst Tageskasse, dann Guthaben kürzen
    v_cut_e := least(v_ea, v_excess); v_cut_c := v_excess - v_cut_e;
    v_ea := v_ea - v_cut_e; v_cr := v_cr - v_cut_c; v_bucket := 0;
    update app_users set flagged=true, flag_reason=left(to_char(now(),'YYYY-MM-DD HH24:MI')||': '||to_char(v_excess,'FM999999999999')||' € abgezogen', 200) where id=v_uid;
  else
    v_bucket := v_bucket - greatest(0, v_w_new - v_w_old);
  end if;
  p_data := jsonb_set(jsonb_set(p_data,'{credits}',to_jsonb(v_cr)),'{earnings}',to_jsonb(v_ea));

  insert into app_saves(user_id, data, updated_at, earn_bucket, checked_at) values (v_uid, p_data, now(), v_bucket, now())
    on conflict (user_id) do update set data=excluded.data, updated_at=now(), earn_bucket=excluded.earn_bucket, checked_at=now();
  if v_excess > 0 then
    return json_build_object('ok',true,'corrected',true,'cut_earnings',v_cut_e,'cut_credits',v_cut_c,'credits',v_cr,'earnings',v_ea);
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

drop function if exists app_change_password(uuid,text);
-- Altes Passwort nötig (Google-Konten ohne Passwort können eines festlegen); danach nur diese Sitzung gültig
create or replace function app_change_password(p_token uuid, p_old text, p_new text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid; v_hash text;
begin
  v_uid := _uid(p_token); if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  select pass_hash into v_hash from app_users where id=v_uid;
  if v_hash is not null and v_hash <> crypt(coalesce(p_old,''), v_hash) then return json_build_object('error','Aktuelles Passwort ist falsch'); end if;
  if length(coalesce(p_new,''))<8 then return json_build_object('error','Passwort zu kurz (min. 8 Zeichen)'); end if;
  update app_users set pass_hash=crypt(p_new, gen_salt('bf',10)) where id=v_uid;
  delete from app_sessions where user_id=v_uid and token_hash<>_token_hash(p_token);
  return json_build_object('ok',true);
end; $$;

create or replace function app_delete_account(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid;
begin
  v_uid := _uid(p_token); if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  delete from app_users where id=v_uid; return json_build_object('ok',true);
end; $$;

grant execute on all functions in schema public to anon, authenticated;
-- Interne Hilfsfunktionen nicht von außen aufrufbar
revoke execute on function _uid(uuid), _maint(), _new_session(uuid), _token_hash(uuid), _client_ip(), _login_locked(text[]), _login_fail(text[]),
  _jnum(jsonb,text), _jlevel(jsonb,int), _jarr(jsonb,text), _assets(jsonb), _vehicle_count(jsonb) from public, anon, authenticated;

notify pgrst, 'reload schema';
