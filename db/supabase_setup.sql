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
  ('vehicle','lhf10',300000),
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
  v_uid uuid; v_old jsonb; v_bucket numeric; v_at timestamptz; v_adj numeric; v_gain numeric; v_used numeric;
  v_rate numeric; v_cap numeric; v_w_old numeric; v_w_new numeric; v_excess numeric;
  v_cr numeric; v_ea numeric; v_cut_e numeric := 0; v_cut_c numeric := 0;
  c_per_veh_h constant numeric := 1000000;   -- max. Einnahmen je Fahrzeug und Stunde
  c_cap_h     constant numeric := 12;        -- Budget reicht höchstens für 12 Stunden
begin
  v_uid := _uid(p_token); if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  if jsonb_typeof(p_data) is distinct from 'object' then return json_build_object('error','Ungültiger Spielstand'); end if;
  select data, earn_bucket, checked_at, econ_adjust into v_old, v_bucket, v_at, v_adj from app_saves where user_id=v_uid for update;
  v_adj := greatest(0, coalesce(v_adj,0));                                    -- abgeholte Gutschriften (Verbandskasse u. a.)

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
  v_excess := ceil(v_w_new - (v_w_old + floor(v_bucket) + v_adj));   -- ganze Euro
  if v_excess > 0 then
    -- abgleichen: erst Tageskasse, dann Guthaben kürzen
    v_cut_e := least(v_ea, v_excess); v_cut_c := v_excess - v_cut_e;
    v_ea := v_ea - v_cut_e; v_cr := v_cr - v_cut_c; v_bucket := 0; v_adj := 0;
    update app_users set flagged=true, flag_reason=left(to_char(now(),'YYYY-MM-DD HH24:MI')||': '||to_char(v_excess,'FM999999999999')||' € abgezogen', 200) where id=v_uid;
  else
    v_gain := greatest(0, v_w_new - v_w_old); v_used := least(v_adj, v_gain);   -- Gutschriften zuerst, Rest aus dem Budget
    v_adj := v_adj - v_used; v_bucket := v_bucket - (v_gain - v_used);
  end if;
  p_data := jsonb_set(jsonb_set(p_data,'{credits}',to_jsonb(v_cr)),'{earnings}',to_jsonb(v_ea));

  insert into app_saves(user_id, data, updated_at, earn_bucket, checked_at, econ_adjust) values (v_uid, p_data, now(), v_bucket, now(), v_adj)
    on conflict (user_id) do update set data=excluded.data, updated_at=now(), earn_bucket=excluded.earn_bucket, checked_at=now(), econ_adjust=excluded.econ_adjust;
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
  -- Gründer: Leitung an das dienstälteste Mitglied übergeben, sonst Verband auflösen
  update app_alliances a set owner=(select m.user_id from app_alliance_members m where m.alliance_id=a.id and m.user_id<>v_uid order by m.joined_at limit 1)
    where a.owner=v_uid and exists(select 1 from app_alliance_members m where m.alliance_id=a.id and m.user_id<>v_uid);
  delete from app_alliances where owner=v_uid;
  delete from app_users where id=v_uid; return json_build_object('ok',true);
end; $$;

/* ===========================================================================
   VERBÄNDE (Teil 1: Grundlage)
   Verband gründen/beitreten, Rollen mit Rechten, Verbandskasse mit Kassenbuch,
   Auszahlungen mit Wochenlimit, Wachen der Mitglieder auf der Karte.
   Rechte: members (Mitglieder verwalten), roles (Rollen verwalten),
           finance (Finanzen), moderate (News/Forum/Regeln). Gründer: alle.
   =========================================================================== */
create table if not exists app_alliances (
  id uuid primary key default gen_random_uuid(), name text not null, tag text not null, description text not null default '',
  owner uuid not null references app_users(id), open boolean not null default false,
  kasse bigint not null default 0, payout_limit bigint not null default 2000000, ranking_public boolean not null default true,
  created_at timestamptz not null default now() );
create unique index if not exists app_alliances_name on app_alliances(lower(name));
create unique index if not exists app_alliances_tag on app_alliances(lower(tag));
create table if not exists app_alliance_members (
  user_id uuid primary key references app_users(id) on delete cascade, alliance_id uuid not null references app_alliances(id) on delete cascade,
  joined_at timestamptz not null default now(), auto_pct numeric not null default 0 );
create index if not exists app_alliance_members_a on app_alliance_members(alliance_id);
create table if not exists app_alliance_roles (
  id uuid primary key default gen_random_uuid(), alliance_id uuid not null references app_alliances(id) on delete cascade,
  name text not null, color text not null default '#a78bfa', position int not null default 100, perms text[] not null default '{}' );
create table if not exists app_alliance_member_roles (
  user_id uuid not null references app_users(id) on delete cascade, role_id uuid not null references app_alliance_roles(id) on delete cascade,
  primary key (user_id, role_id) );
create table if not exists app_alliance_requests (            -- Bewerbungen (apply) und Einladungen (invite)
  alliance_id uuid not null references app_alliances(id) on delete cascade, user_id uuid not null references app_users(id) on delete cascade,
  kind text not null check (kind in ('apply','invite')), created_at timestamptz not null default now(), primary key (alliance_id, user_id) );
create table if not exists app_alliance_ledger (
  id bigserial primary key, alliance_id uuid not null references app_alliances(id) on delete cascade, user_id uuid references app_users(id) on delete set null,
  kind text not null, amount bigint not null, note text not null default '', created_at timestamptz not null default now() );
create index if not exists app_alliance_ledger_a on app_alliance_ledger(alliance_id, created_at desc);
create table if not exists app_grants (                       -- Gutschriften (z. B. Auszahlung aus der Verbandskasse), holt der Browser ab
  id bigserial primary key, user_id uuid not null references app_users(id) on delete cascade, amount bigint not null, note text not null default '',
  created_at timestamptz not null default now(), claimed_at timestamptz );
alter table app_saves add column if not exists econ_adjust numeric not null default 0;   -- abgeholte Gutschriften, bei der Geldprüfung erlaubt

alter table app_alliances enable row level security; alter table app_alliance_members enable row level security;
alter table app_alliance_roles enable row level security; alter table app_alliance_member_roles enable row level security;
alter table app_alliance_requests enable row level security; alter table app_alliance_ledger enable row level security;
alter table app_grants enable row level security;
revoke all on app_alliances, app_alliance_members, app_alliance_roles, app_alliance_member_roles, app_alliance_requests, app_alliance_ledger, app_grants from anon, authenticated;

create or replace function _ally_of(p_uid uuid) returns uuid language sql stable security definer set search_path=public, extensions as $$
  select alliance_id from app_alliance_members where user_id=p_uid; $$;
create or replace function _ally_is_owner(p_uid uuid) returns boolean language sql stable security definer set search_path=public, extensions as $$
  select exists(select 1 from app_alliances a join app_alliance_members m on m.alliance_id=a.id where m.user_id=p_uid and a.owner=p_uid); $$;
create or replace function _ally_perm(p_uid uuid, p_perm text) returns boolean language sql stable security definer set search_path=public, extensions as $$
  select _ally_is_owner(p_uid) or exists(select 1 from app_alliance_member_roles mr join app_alliance_roles r on r.id=mr.role_id
    where mr.user_id=p_uid and p_perm = any(r.perms)); $$;
-- Höchste Rolle (kleinste Position); Gründer = -1, ohne Rolle = 100000
create or replace function _ally_rank(p_uid uuid) returns int language sql stable security definer set search_path=public, extensions as $$
  select case when _ally_is_owner(p_uid) then -1 else coalesce((select min(r.position) from app_alliance_member_roles mr join app_alliance_roles r on r.id=mr.role_id where mr.user_id=p_uid),100000) end; $$;
-- Geld vom gespeicherten Guthaben abziehen (Einzahlung, Gründung). Der Browser zieht es selbst auch ab; tut er es nicht, korrigiert app_save.
create or replace function _take_credits(p_uid uuid, p_amount bigint) returns boolean language plpgsql security definer set search_path=public, extensions as $$
declare v_cr numeric;
begin
  select _jnum(data,'credits') into v_cr from app_saves where user_id=p_uid for update;
  if v_cr is null or v_cr < p_amount then return false; end if;
  update app_saves set data=jsonb_set(data,'{credits}',to_jsonb(v_cr-p_amount)) where user_id=p_uid;
  return true;
end; $$;
create or replace function _berlin_day(t timestamptz) returns date language sql immutable as $$ select (t at time zone 'Europe/Berlin')::date; $$;

create or replace function ally_create(p_token uuid, p_name text, p_tag text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_id uuid; c_cost constant bigint := 1000000;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  if _ally_of(v_uid) is not null then return json_build_object('error','Du bist bereits in einem Verband'); end if;
  p_name := btrim(coalesce(p_name,'')); p_tag := upper(btrim(coalesce(p_tag,'')));
  if length(p_name) < 3 or length(p_name) > 40 then return json_build_object('error','Name: 3–40 Zeichen'); end if;
  if p_tag !~ '^[A-Z0-9]{2,5}$' then return json_build_object('error','Kürzel: 2–5 Buchstaben oder Ziffern'); end if;
  if exists(select 1 from app_alliances where lower(name)=lower(p_name) or lower(tag)=lower(p_tag)) then return json_build_object('error','Name oder Kürzel ist schon vergeben'); end if;
  if not _take_credits(v_uid, c_cost) then return json_build_object('error','Nicht genug Guthaben (1.000.000 € nötig)'); end if;
  insert into app_alliances(name, tag, owner) values (p_name, p_tag, v_uid) returning id into v_id;
  insert into app_alliance_members(user_id, alliance_id) values (v_uid, v_id);
  delete from app_alliance_requests where user_id=v_uid;
  insert into app_alliance_roles(alliance_id, name, color, position, perms) values (v_id,'Leitung','#f59e0b',10,'{members,roles,finance,moderate}'),(v_id,'Mitglied','#a78bfa',90,'{}');
  insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_id, v_uid, 'gruendung', 0, 'Verband gegründet');
  return json_build_object('ok',true,'id',v_id,'cost',c_cost);
end; $$;

create or replace function ally_list(p_token uuid, p_search text)
returns json language sql security definer set search_path=public, extensions as $$
  select coalesce(json_agg(x order by x.members desc), '[]'::json) from (
    select a.id, a.name, a.tag, a.description, a.open, (select count(*) from app_alliance_members m where m.alliance_id=a.id) as members,
      exists(select 1 from app_alliance_requests r where r.alliance_id=a.id and r.user_id=_uid(p_token) and r.kind='apply') as applied
    from app_alliances a where _uid(p_token) is not null and (coalesce(p_search,'')='' or a.name ilike '%'||p_search||'%' or a.tag ilike '%'||p_search||'%')
    limit 50) x; $$;

create or replace function _ally_join(p_uid uuid, p_aid uuid) returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_role uuid;
begin
  if _ally_of(p_uid) is not null then return json_build_object('error','Bereits in einem Verband'); end if;
  if (select count(*) from app_alliance_members where alliance_id=p_aid) >= 100 then return json_build_object('error','Der Verband ist voll (100 Mitglieder)'); end if;
  insert into app_alliance_members(user_id, alliance_id) values (p_uid, p_aid);
  delete from app_alliance_requests where user_id=p_uid;
  select id into v_role from app_alliance_roles where alliance_id=p_aid order by position desc limit 1;   -- unterste Rolle
  if v_role is not null then insert into app_alliance_member_roles values (p_uid, v_role) on conflict do nothing; end if;
  insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (p_aid, p_uid, 'beitritt', 0, 'beigetreten');
  return json_build_object('ok',true,'joined',true);
end; $$;

create or replace function ally_apply(p_token uuid, p_aid uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_open boolean;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  select open into v_open from app_alliances where id=p_aid; if v_open is null then return json_build_object('error','Verband nicht gefunden'); end if;
  if _ally_of(v_uid) is not null then return json_build_object('error','Du bist bereits in einem Verband'); end if;
  if v_open then return _ally_join(v_uid, p_aid); end if;
  insert into app_alliance_requests(alliance_id, user_id, kind) values (p_aid, v_uid, 'apply') on conflict (alliance_id,user_id) do nothing;
  return json_build_object('ok',true,'applied',true);
end; $$;

create or replace function ally_invite(p_token uuid, p_username text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); v_t uuid;
begin
  if v_aid is null or not _ally_perm(v_uid,'members') then return json_build_object('error','Keine Berechtigung'); end if;
  select id into v_t from app_users where lower(username)=lower(btrim(p_username)); if v_t is null then return json_build_object('error','Spieler nicht gefunden'); end if;
  if _ally_of(v_t) is not null then return json_build_object('error','Spieler ist bereits in einem Verband'); end if;
  insert into app_alliance_requests(alliance_id, user_id, kind) values (v_aid, v_t, 'invite') on conflict (alliance_id,user_id) do update set kind='invite', created_at=now();
  return json_build_object('ok',true);
end; $$;

-- Bewerbung annehmen/ablehnen (Recht members) oder Einladung annehmen/ablehnen (eingeladener Spieler)
create or replace function ally_request_answer(p_token uuid, p_aid uuid, p_user uuid, p_accept boolean)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_kind text;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  select kind into v_kind from app_alliance_requests where alliance_id=p_aid and user_id=coalesce(p_user,v_uid);
  if v_kind is null then return json_build_object('error','Anfrage nicht gefunden'); end if;
  if v_kind='invite' and coalesce(p_user,v_uid)<>v_uid then return json_build_object('error','Keine Berechtigung'); end if;
  if v_kind='apply' and not (_ally_of(v_uid)=p_aid and _ally_perm(v_uid,'members')) then return json_build_object('error','Keine Berechtigung'); end if;
  if not p_accept then delete from app_alliance_requests where alliance_id=p_aid and user_id=coalesce(p_user,v_uid); return json_build_object('ok',true); end if;
  return _ally_join(coalesce(p_user,v_uid), p_aid);
end; $$;

create or replace function _ally_remove(p_uid uuid) returns void language plpgsql security definer set search_path=public, extensions as $$
declare v_aid uuid := _ally_of(p_uid);
begin
  delete from app_alliance_member_roles where user_id=p_uid;
  delete from app_alliance_members where user_id=p_uid;
  if v_aid is not null then insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_aid, p_uid, 'austritt', 0, 'ausgetreten'); end if;
end; $$;

create or replace function ally_leave(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token);
begin
  if v_uid is null or _ally_of(v_uid) is null then return json_build_object('error','Kein Verband'); end if;
  if _ally_is_owner(v_uid) then return json_build_object('error','Als Gründer erst die Leitung übertragen oder den Verband auflösen'); end if;
  perform _ally_remove(v_uid); return json_build_object('ok',true);
end; $$;

create or replace function ally_kick(p_token uuid, p_user uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null or not _ally_perm(v_uid,'members') or _ally_of(p_user) is distinct from v_aid or p_user=v_uid then return json_build_object('error','Keine Berechtigung'); end if;
  if _ally_rank(p_user) <= _ally_rank(v_uid) then return json_build_object('error','Nur Mitglieder mit niedrigerer Rolle'); end if;
  perform _ally_remove(p_user); return json_build_object('ok',true);
end; $$;

create or replace function ally_transfer(p_token uuid, p_user uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null or not _ally_is_owner(v_uid) or _ally_of(p_user) is distinct from v_aid or p_user=v_uid then return json_build_object('error','Keine Berechtigung'); end if;
  update app_alliances set owner=p_user where id=v_aid; return json_build_object('ok',true);
end; $$;

create or replace function ally_dissolve(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null or not _ally_is_owner(v_uid) then return json_build_object('error','Nur der Gründer kann den Verband auflösen'); end if;
  delete from app_alliance_member_roles where user_id in (select user_id from app_alliance_members where alliance_id=v_aid);
  delete from app_alliances where id=v_aid; return json_build_object('ok',true);
end; $$;

-- Rollen speichern: [{id?, name, color, position, perms[], delete?}] — nur Rollen unterhalb der eigenen höchsten Rolle
create or replace function ally_roles_save(p_token uuid, p_roles jsonb)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); v_rank int; r jsonb; v_pos int; v_perms text[]; v_old int;
begin
  if v_aid is null or not _ally_perm(v_uid,'roles') then return json_build_object('error','Keine Berechtigung'); end if;
  v_rank := _ally_rank(v_uid);
  for r in select * from jsonb_array_elements(coalesce(p_roles,'[]'::jsonb)) loop
    v_pos := greatest(1, least(999, coalesce((r->>'position')::int, 100)));
    select array_agg(p) into v_perms from jsonb_array_elements_text(coalesce(r->'perms','[]'::jsonb)) p where p in ('members','roles','finance','moderate');
    if r ? 'id' and (r->>'id') <> '' then
      select position into v_old from app_alliance_roles where id=(r->>'id')::uuid and alliance_id=v_aid;
      if v_old is null then continue; end if;
      if v_rank <> -1 and (v_old <= v_rank or v_pos <= v_rank) then continue; end if;   -- eigene oder höhere Rollen bleiben unangetastet
      if coalesce((r->>'delete')::boolean,false) then delete from app_alliance_roles where id=(r->>'id')::uuid; continue; end if;
      update app_alliance_roles set name=left(btrim(coalesce(r->>'name','Rolle')),30), color=coalesce(substring(r->>'color' from '^#[0-9a-fA-F]{6}$'),color), position=v_pos, perms=coalesce(v_perms,'{}') where id=(r->>'id')::uuid;
    else
      if v_rank <> -1 and v_pos <= v_rank then continue; end if;
      if (select count(*) from app_alliance_roles where alliance_id=v_aid) >= 25 then exit; end if;
      insert into app_alliance_roles(alliance_id, name, color, position, perms) values (v_aid, left(btrim(coalesce(r->>'name','Rolle')),30), coalesce(substring(r->>'color' from '^#[0-9a-fA-F]{6}$'),'#a78bfa'), v_pos, coalesce(v_perms,'{}'));
    end if;
  end loop;
  return json_build_object('ok',true);
end; $$;

create or replace function ally_member_roles(p_token uuid, p_user uuid, p_role_ids uuid[])
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); v_rank int := _ally_rank(_uid(p_token));
begin
  if v_aid is null or not _ally_perm(v_uid,'roles') or _ally_of(p_user) is distinct from v_aid then return json_build_object('error','Keine Berechtigung'); end if;
  if p_user<>v_uid and v_rank <> -1 and _ally_rank(p_user) <= v_rank then return json_build_object('error','Nur Mitglieder mit niedrigerer Rolle'); end if;
  -- nur Rollen unterhalb der eigenen dürfen gesetzt/entfernt werden
  delete from app_alliance_member_roles mr using app_alliance_roles r where mr.role_id=r.id and mr.user_id=p_user and (v_rank=-1 or r.position > v_rank);
  insert into app_alliance_member_roles(user_id, role_id) select p_user, r.id from app_alliance_roles r
    where r.alliance_id=v_aid and r.id = any(coalesce(p_role_ids,'{}')) and (v_rank=-1 or r.position > v_rank) on conflict do nothing;
  return json_build_object('ok',true);
end; $$;

-- Einzahlung (kind 'einzahlung' oder 'auto' = automatischer Anteil der Tageseinnahmen)
create or replace function ally_deposit(p_token uuid, p_amount bigint, p_auto boolean)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null then return json_build_object('error','Kein Verband'); end if;
  if coalesce(p_amount,0) <= 0 or p_amount > 1000000000 then return json_build_object('error','Ungültiger Betrag'); end if;
  if not _take_credits(v_uid, p_amount) then return json_build_object('error','Nicht genug Guthaben'); end if;
  update app_alliances set kasse=kasse+p_amount where id=v_aid;
  insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_aid, v_uid, case when p_auto then 'auto' else 'einzahlung' end, p_amount, case when p_auto then 'Anteil der Tageseinnahmen' else '' end);
  return json_build_object('ok',true);
end; $$;

create or replace function ally_auto_pct(p_token uuid, p_pct numeric)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token);
begin
  if _ally_of(v_uid) is null then return json_build_object('error','Kein Verband'); end if;
  update app_alliance_members set auto_pct=greatest(0,least(10,coalesce(p_pct,0))) where user_id=v_uid; return json_build_object('ok',true);
end; $$;

-- Auszahlung an ein Mitglied: Recht finance, höchstens payout_limit (≤ 2 Mio.) je Mitglied in 7 Tagen, erst nach 3 Tagen Mitgliedschaft
create or replace function ally_payout(p_token uuid, p_user uuid, p_amount bigint, p_note text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); v_a app_alliances; v_week bigint; v_joined timestamptz;
begin
  if v_aid is null or not _ally_perm(v_uid,'finance') then return json_build_object('error','Keine Berechtigung'); end if;
  select joined_at into v_joined from app_alliance_members where user_id=p_user and alliance_id=v_aid;
  if v_joined is null then return json_build_object('error','Kein Mitglied dieses Verbands'); end if;
  if v_joined > now() - interval '3 days' then return json_build_object('error','Auszahlungen erst nach 3 Tagen Mitgliedschaft'); end if;
  select * into v_a from app_alliances where id=v_aid for update;
  if coalesce(p_amount,0) <= 0 or p_amount > v_a.kasse then return json_build_object('error','Ungültiger Betrag oder zu wenig in der Kasse'); end if;
  select coalesce(sum(-amount),0) into v_week from app_alliance_ledger where alliance_id=v_aid and user_id=p_user and kind='auszahlung' and created_at > now() - interval '7 days';
  if v_week + p_amount > least(v_a.payout_limit, 2000000) then
    return json_build_object('error','Wochenlimit überschritten: noch '||greatest(0,least(v_a.payout_limit,2000000)-v_week)||' € möglich'); end if;
  update app_alliances set kasse=kasse-p_amount where id=v_aid;
  insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_aid, p_user, 'auszahlung', -p_amount, left(coalesce(p_note,''),100)||' (von '||(select username from app_users where id=v_uid)||')');
  insert into app_grants(user_id, amount, note) values (p_user, p_amount, 'Auszahlung aus der Verbandskasse');
  return json_build_object('ok',true);
end; $$;

create or replace function ally_settings(p_token uuid, p_settings jsonb)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null then return json_build_object('error','Kein Verband'); end if;
  if _ally_perm(v_uid,'members') then
    update app_alliances set open=coalesce((p_settings->>'open')::boolean, open), description=left(coalesce(p_settings->>'description', description),500) where id=v_aid; end if;
  if _ally_perm(v_uid,'finance') then
    update app_alliances set payout_limit=greatest(0,least(2000000,coalesce((p_settings->>'payout_limit')::bigint, payout_limit))),
      ranking_public=coalesce((p_settings->>'ranking_public')::boolean, ranking_public) where id=v_aid; end if;
  return json_build_object('ok',true);
end; $$;

-- Alles für das Verbandsfenster
create or replace function ally_overview(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); v_a app_alliances; v_day date := _berlin_day(now()); v_fin boolean;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  if v_aid is null then
    return json_build_object('member',false,'invites',coalesce((select json_agg(json_build_object('alliance_id',a.id,'name',a.name,'tag',a.tag)) from app_alliance_requests r join app_alliances a on a.id=r.alliance_id where r.user_id=v_uid and r.kind='invite'),'[]'::json));
  end if;
  select * into v_a from app_alliances where id=v_aid; v_fin := _ally_perm(v_uid,'finance');
  return json_build_object('member',true,'me',v_uid,
    'alliance',json_build_object('id',v_a.id,'name',v_a.name,'tag',v_a.tag,'description',v_a.description,'open',v_a.open,'kasse',v_a.kasse,
      'payout_limit',v_a.payout_limit,'ranking_public',v_a.ranking_public,'owner',v_a.owner,'created_at',v_a.created_at),
    'perms',json_build_object('owner',_ally_is_owner(v_uid),'members',_ally_perm(v_uid,'members'),'roles',_ally_perm(v_uid,'roles'),'finance',v_fin,'moderate',_ally_perm(v_uid,'moderate'),'rank',_ally_rank(v_uid)),
    'roles',coalesce((select json_agg(json_build_object('id',id,'name',name,'color',color,'position',position,'perms',perms) order by position) from app_alliance_roles where alliance_id=v_aid),'[]'::json),
    'members',coalesce((select json_agg(json_build_object('id',m.user_id,'name',u.username,'joined_at',m.joined_at,'auto_pct',m.auto_pct,'rank',_ally_rank(m.user_id),
        'roles',coalesce((select json_agg(mr.role_id) from app_alliance_member_roles mr where mr.user_id=m.user_id),'[]'::json),
        'today',coalesce((select sum(amount) from app_alliance_ledger l where l.alliance_id=v_aid and l.user_id=m.user_id and l.kind in ('einzahlung','auto') and _berlin_day(l.created_at)=v_day),0),
        'month',coalesce((select sum(amount) from app_alliance_ledger l where l.alliance_id=v_aid and l.user_id=m.user_id and l.kind in ('einzahlung','auto') and l.created_at > now()-interval '30 days'),0),
        'total',coalesce((select sum(amount) from app_alliance_ledger l where l.alliance_id=v_aid and l.user_id=m.user_id and l.kind in ('einzahlung','auto')),0),
        'paid_week',coalesce((select sum(-amount) from app_alliance_ledger l where l.alliance_id=v_aid and l.user_id=m.user_id and l.kind='auszahlung' and l.created_at > now()-interval '7 days'),0))
      order by u.username) from app_alliance_members m join app_users u on u.id=m.user_id where m.alliance_id=v_aid),'[]'::json),
    'requests',case when _ally_perm(v_uid,'members') then coalesce((select json_agg(json_build_object('user_id',r.user_id,'name',u.username,'kind',r.kind,'created_at',r.created_at)) from app_alliance_requests r join app_users u on u.id=r.user_id where r.alliance_id=v_aid),'[]'::json) else '[]'::json end,
    'ledger',coalesce((select json_agg(x) from (select l.kind, l.amount, l.note, l.created_at, u.username as name from app_alliance_ledger l left join app_users u on u.id=l.user_id where l.alliance_id=v_aid order by l.created_at desc limit 100) x),'[]'::json),
    'stats',json_build_object(
      'in_today',coalesce((select sum(amount) from app_alliance_ledger where alliance_id=v_aid and kind in ('einzahlung','auto') and _berlin_day(created_at)=v_day),0),
      'in_month',coalesce((select sum(amount) from app_alliance_ledger where alliance_id=v_aid and kind in ('einzahlung','auto') and created_at > now()-interval '30 days'),0),
      'in_total',coalesce((select sum(amount) from app_alliance_ledger where alliance_id=v_aid and kind in ('einzahlung','auto')),0),
      'out_total',coalesce((select sum(-amount) from app_alliance_ledger where alliance_id=v_aid and kind='auszahlung'),0)),
    'ranking_visible', v_a.ranking_public or v_fin);
end; $$;

-- Wachen und Gebäude der anderen Mitglieder (aus deren Spielständen)
create or replace function ally_map(p_token uuid)
returns json language sql security definer set search_path=public, extensions as $$
  select coalesce(json_agg(json_build_object('owner',u.username,
      'stations',coalesce((select json_agg(json_build_object('name',st->>'name','lat',st->'lat','lng',st->'lng','level',st->'level',
          'ready',coalesce((st->>'readyAt')::numeric,0) <= extract(epoch from now())*1000)) from jsonb_array_elements(_jarr(s.data,'stations')) st),'[]'::json),
      'buildings',coalesce((select json_agg(json_build_object('typeId',b->>'typeId','name',b->>'name','lat',b->'lat','lng',b->'lng',
          'ready',coalesce((b->>'readyAt')::numeric,0) <= extract(epoch from now())*1000)) from jsonb_array_elements(_jarr(s.data,'buildings')) b),'[]'::json))), '[]'::json)
  from app_alliance_members m join app_users u on u.id=m.user_id join app_saves s on s.user_id=m.user_id
  where m.alliance_id=_ally_of(_uid(p_token)) and m.user_id<>_uid(p_token); $$;

-- Gutschriften abholen (alle 10 s): werden bei der nächsten Geldprüfung als erlaubter Zuwachs angerechnet
create or replace function ally_poll(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_sum numeric; v_list json;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  select coalesce(json_agg(json_build_object('amount',amount,'note',note)),'[]'::json), coalesce(sum(amount),0) into v_list, v_sum
    from app_grants where user_id=v_uid and claimed_at is null;
  if v_sum > 0 then
    update app_grants set claimed_at=now() where user_id=v_uid and claimed_at is null;
    update app_saves set econ_adjust=econ_adjust+v_sum where user_id=v_uid;
  end if;
  return json_build_object('ok',true,'alliance',_ally_of(v_uid),'grants',v_list,
    'auto_pct',(select auto_pct from app_alliance_members where user_id=v_uid));
end; $$;

grant execute on all functions in schema public to anon, authenticated;
-- Interne Hilfsfunktionen nicht von außen aufrufbar
revoke execute on function _uid(uuid), _maint(), _new_session(uuid), _token_hash(uuid), _client_ip(), _login_locked(text[]), _login_fail(text[]),
  _jnum(jsonb,text), _jlevel(jsonb,int), _jarr(jsonb,text), _assets(jsonb), _vehicle_count(jsonb),
  _ally_of(uuid), _ally_is_owner(uuid), _ally_perm(uuid,text), _ally_rank(uuid), _take_credits(uuid,bigint), _ally_join(uuid,uuid), _ally_remove(uuid) from public, anon, authenticated;

notify pgrst, 'reload schema';
