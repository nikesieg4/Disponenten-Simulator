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
  ('vehicle','gw_rettmat',150000),
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
  + coalesce((select sum(p.price) from jsonb_array_elements(_jarr(d,'buildings')) b join app_prices p on p.kind='academy' and p.id='L'||_jlevel(b,5) where b->>'typeId'='academy'),0)
  -- bezahlte, noch nicht fertige Erweiterungen (stornierbar, volle Erstattung)
  + coalesce((select sum(least(10000000, greatest(0, _jnum(e,'paid')))) from (select st from jsonb_array_elements(_jarr(d,'stations')) st
      union all select b from jsonb_array_elements(_jarr(d,'buildings')) b) o(x), jsonb_array_elements(_jarr(o.x,'exts')) e
      where _jnum(e,'readyAt') > extract(epoch from now())*1000),0); $$;
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
  if v_excess <= 0 then                                                   -- Quest-Fortschritt aus den neuen, vom Anti-Cheat gedeckten Einnahmen
    begin perform _quest_track(v_uid, p_data, coalesce(v_gain,0)); exception when others then null; end;
  end if;
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
   Rechte: members (Bewerbungen/Einladungen), roles (Rollen verwalten), finance (Finanzen),
           moderate (News/Forum/Regeln, Chat-Nachrichten löschen), kick, ban, timeout (Chat). Gründer: alle.
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

/* ---------- Verbände Teil 2a: Kick/Bann/Timeout, Verbandschat, Verbandsfunk ---------- */
create table if not exists app_migrations ( key text primary key, at timestamptz not null default now() );
create table if not exists app_alliance_bans (
  alliance_id uuid not null references app_alliances(id) on delete cascade, user_id uuid not null references app_users(id) on delete cascade,
  until timestamptz, reason text not null default '', by_user uuid references app_users(id) on delete set null, created_at timestamptz not null default now(),
  primary key (alliance_id, user_id) );
create table if not exists app_alliance_timeouts (
  alliance_id uuid not null references app_alliances(id) on delete cascade, user_id uuid not null references app_users(id) on delete cascade,
  until timestamptz not null, primary key (alliance_id, user_id) );
create table if not exists app_alliance_chat (
  id bigserial primary key, alliance_id uuid not null references app_alliances(id) on delete cascade, user_id uuid references app_users(id) on delete set null,
  msg text not null, deleted boolean not null default false, created_at timestamptz not null default now() );
create index if not exists app_alliance_chat_a on app_alliance_chat(alliance_id, id);
create table if not exists app_alliance_radio (
  id bigserial primary key, alliance_id uuid not null references app_alliances(id) on delete cascade, user_id uuid not null references app_users(id) on delete cascade,
  vehicle text not null, status int, note text not null default '', created_at timestamptz not null default now() );
create index if not exists app_alliance_radio_a on app_alliance_radio(alliance_id, id);
alter table app_migrations enable row level security; alter table app_alliance_bans enable row level security;
alter table app_alliance_timeouts enable row level security; alter table app_alliance_chat enable row level security; alter table app_alliance_radio enable row level security;
revoke all on app_migrations, app_alliance_bans, app_alliance_timeouts, app_alliance_chat, app_alliance_radio from anon, authenticated;

-- Einmalig: bestehende Rollen mit „Mitglieder verwalten“ bekommen „Kick“ (vorher dasselbe Recht), Leitung zusätzlich Bann/Timeout
do $$ begin
  if not exists(select 1 from app_migrations where key='ally_kick_ban_timeout') then
    update app_alliance_roles set perms=array(select distinct unnest(perms||'{kick}'::text[])) where 'members'=any(perms);
    update app_alliance_roles set perms=array(select distinct unnest(perms||'{ban,timeout}'::text[])) where 'members'=any(perms) and 'roles'=any(perms);
    insert into app_migrations(key) values ('ally_kick_ban_timeout');
  end if;
end $$;

create or replace function _ally_banned(p_aid uuid, p_uid uuid) returns boolean language sql stable security definer set search_path=public, extensions as $$
  select exists(select 1 from app_alliance_bans where alliance_id=p_aid and user_id=p_uid and (until is null or until > now())); $$;

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
  insert into app_alliance_roles(alliance_id, name, color, position, perms) values (v_id,'Leitung','#f59e0b',10,'{members,roles,finance,moderate,kick,ban,timeout}'),(v_id,'Mitglied','#a78bfa',90,'{}');
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
  if _ally_banned(p_aid, p_uid) then return json_build_object('error','Für diesen Verband gesperrt'); end if;
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
  if _ally_banned(p_aid, v_uid) then return json_build_object('error','Du bist für diesen Verband gesperrt'); end if;
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
  if _ally_banned(v_aid, v_t) then return json_build_object('error','Spieler ist gesperrt (erst entsperren)'); end if;
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
  if v_aid is null or not _ally_perm(v_uid,'kick') or _ally_of(p_user) is distinct from v_aid or p_user=v_uid then return json_build_object('error','Keine Berechtigung'); end if;
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
    select array_agg(p) into v_perms from jsonb_array_elements_text(coalesce(r->'perms','[]'::jsonb)) p where p in ('members','roles','finance','moderate','kick','ban','timeout','courses');
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
      ranking_public=coalesce((p_settings->>'ranking_public')::boolean, ranking_public),
      academy_limit=greatest(1,least(10,coalesce((p_settings->>'academy_limit')::int, academy_limit))) where id=v_aid; end if;
  return json_build_object('ok',true);
end; $$;

-- Bann: entfernt (falls Mitglied) und sperrt Bewerbung/Einladung; p_days null = dauerhaft
create or replace function ally_ban(p_token uuid, p_user uuid, p_days int, p_reason text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null or not _ally_perm(v_uid,'ban') or p_user=v_uid then return json_build_object('error','Keine Berechtigung'); end if;
  if _ally_of(p_user)=v_aid then
    if _ally_rank(p_user) <= _ally_rank(v_uid) then return json_build_object('error','Nur Mitglieder mit niedrigerer Rolle'); end if;
    perform _ally_remove(p_user);
  end if;
  delete from app_alliance_requests where alliance_id=v_aid and user_id=p_user;
  insert into app_alliance_bans(alliance_id, user_id, until, reason, by_user) values (v_aid, p_user, case when p_days is null or p_days<=0 then null else now()+make_interval(days=>p_days) end, left(coalesce(p_reason,''),200), v_uid)
    on conflict (alliance_id,user_id) do update set until=excluded.until, reason=excluded.reason, by_user=excluded.by_user, created_at=now();
  insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_aid, p_user, 'bann', 0, case when p_days is null or p_days<=0 then 'dauerhaft' else p_days||' Tage' end);
  return json_build_object('ok',true);
end; $$;
create or replace function ally_unban(p_token uuid, p_user uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null or not _ally_perm(v_uid,'ban') then return json_build_object('error','Keine Berechtigung'); end if;
  delete from app_alliance_bans where alliance_id=v_aid and user_id=p_user; return json_build_object('ok',true);
end; $$;
-- Timeout im Chat: p_minutes 0 hebt auf
create or replace function ally_timeout(p_token uuid, p_user uuid, p_minutes int)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null or not _ally_perm(v_uid,'timeout') or _ally_of(p_user) is distinct from v_aid or p_user=v_uid then return json_build_object('error','Keine Berechtigung'); end if;
  if _ally_rank(p_user) <= _ally_rank(v_uid) then return json_build_object('error','Nur Mitglieder mit niedrigerer Rolle'); end if;
  if coalesce(p_minutes,0) <= 0 then delete from app_alliance_timeouts where alliance_id=v_aid and user_id=p_user; return json_build_object('ok',true); end if;
  insert into app_alliance_timeouts values (v_aid, p_user, now()+make_interval(mins=>least(p_minutes,43200)))
    on conflict (alliance_id,user_id) do update set until=excluded.until;
  return json_build_object('ok',true);
end; $$;
create or replace function ally_chat_send(p_token uuid, p_msg text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); v_until timestamptz;
begin
  if v_aid is null then return json_build_object('error','Kein Verband'); end if;
  select until into v_until from app_alliance_timeouts where alliance_id=v_aid and user_id=v_uid and until > now();
  if v_until is not null then return json_build_object('error','Du bist im Chat stummgeschaltet bis '||to_char(v_until at time zone 'Europe/Berlin','DD.MM. HH24:MI')); end if;
  p_msg := btrim(coalesce(p_msg,'')); if p_msg='' then return json_build_object('error','Leere Nachricht'); end if;
  if (select count(*) from app_alliance_chat where user_id=v_uid and created_at > now()-interval '10 seconds') >= 5 then return json_build_object('error','Bitte langsamer schreiben'); end if;
  insert into app_alliance_chat(alliance_id, user_id, msg) values (v_aid, v_uid, left(p_msg,500));
  delete from app_alliance_chat where alliance_id=v_aid and created_at < now()-interval '7 days';
  return json_build_object('ok',true);
end; $$;
create or replace function ally_chat_delete(p_token uuid, p_id bigint)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  update app_alliance_chat set deleted=true, msg='' where id=p_id and alliance_id=v_aid and (user_id=v_uid or _ally_perm(v_uid,'moderate'));
  if not found then return json_build_object('error','Keine Berechtigung'); end if; return json_build_object('ok',true);
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
    'perms',json_build_object('owner',_ally_is_owner(v_uid),'members',_ally_perm(v_uid,'members'),'roles',_ally_perm(v_uid,'roles'),'finance',v_fin,'moderate',_ally_perm(v_uid,'moderate'),
      'kick',_ally_perm(v_uid,'kick'),'ban',_ally_perm(v_uid,'ban'),'timeout',_ally_perm(v_uid,'timeout'),'rank',_ally_rank(v_uid)),
    'bans',case when _ally_perm(v_uid,'ban') then coalesce((select json_agg(json_build_object('user_id',b.user_id,'name',u.username,'until',b.until,'reason',b.reason,'created_at',b.created_at) order by b.created_at desc)
        from app_alliance_bans b join app_users u on u.id=b.user_id where b.alliance_id=v_aid and (b.until is null or b.until > now())),'[]'::json) else '[]'::json end,
    'timeouts',coalesce((select json_object_agg(user_id, until) from app_alliance_timeouts where alliance_id=v_aid and until > now()),'{}'::json),
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
      'buildings',coalesce((select json_agg(json_build_object('typeId',b->>'typeId','name',b->>'name','lat',b->'lat','lng',b->'lng','shared',jsonb_typeof(b->'allyShare')='object',
          'ready',coalesce((b->>'readyAt')::numeric,0) <= extract(epoch from now())*1000)) from jsonb_array_elements(_jarr(s.data,'buildings')) b),'[]'::json))), '[]'::json)
  from app_alliance_members m join app_users u on u.id=m.user_id join app_saves s on s.user_id=m.user_id
  where m.alliance_id=_ally_of(_uid(p_token)) and m.user_id<>_uid(p_token); $$;

-- Gutschriften abholen (alle 10 s): werden bei der nächsten Geldprüfung als erlaubter Zuwachs angerechnet
drop function if exists ally_poll(uuid);
-- p_radio: eigene Funkmeldungen [{vehicle,status,note}]; p_radio_after: zuletzt gesehene Funk-id (null = erster Abruf, nur Startwert);
-- p_chat_after: zuletzt gesehene Chat-id (0 = letzte 100 Nachrichten)
drop function if exists ally_poll(uuid, jsonb, bigint, bigint);
create or replace function ally_poll(p_token uuid, p_radio jsonb default '[]', p_radio_after bigint default null, p_chat_after bigint default 0)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_sum numeric; v_list json; v_aid uuid; v_radio json; v_chat json; v_rmax bigint; v_cmax bigint;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  select coalesce(json_agg(json_build_object('amount',amount,'note',note)),'[]'::json), coalesce(sum(amount),0) into v_list, v_sum
    from app_grants where user_id=v_uid and claimed_at is null;
  if v_sum > 0 then
    update app_grants set claimed_at=now() where user_id=v_uid and claimed_at is null;
    update app_saves set econ_adjust=econ_adjust+v_sum where user_id=v_uid;
  end if;
  v_aid := _ally_of(v_uid);
  if v_aid is not null then
    insert into app_alliance_radio(alliance_id, user_id, vehicle, status, note)
      select v_aid, v_uid, left(coalesce(x->>'vehicle',''),60), case when (x->>'status') ~ '^[1-8]$' then (x->>'status')::int end, left(coalesce(x->>'note',''),120)
      from (select x from jsonb_array_elements(case when jsonb_typeof(p_radio)='array' then p_radio else '[]'::jsonb end) x limit 30) q;
    delete from app_alliance_radio where alliance_id=v_aid and created_at < now()-interval '1 hour';
    select coalesce(max(id),0) into v_rmax from app_alliance_radio where alliance_id=v_aid;
    select coalesce(json_agg(json_build_object('id',r.id,'player',u.username,'vehicle',r.vehicle,'status',r.status,'note',r.note,'at',r.created_at) order by r.id),'[]'::json) into v_radio
      from (select * from app_alliance_radio where alliance_id=v_aid and user_id<>v_uid and id > coalesce(p_radio_after, v_rmax) order by id limit 50) r join app_users u on u.id=r.user_id;
    select coalesce(max(id),0) into v_cmax from app_alliance_chat where alliance_id=v_aid;
    select coalesce(json_agg(json_build_object('id',c.id,'user_id',c.user_id,'name',u.username,'msg',c.msg,'deleted',c.deleted,'at',c.created_at) order by c.id),'[]'::json) into v_chat
      from (select * from app_alliance_chat where alliance_id=v_aid and id > p_chat_after and created_at > now()-interval '7 days' order by id desc limit 100) c left join app_users u on u.id=c.user_id;
  end if;
  return json_build_object('ok',true,'alliance',v_aid,'grants',v_list,'radio',coalesce(v_radio,'[]'::json),'radio_max',coalesce(v_rmax,0),'chat',coalesce(v_chat,'[]'::json),
    'muted_until',(select until from app_alliance_timeouts where alliance_id=v_aid and user_id=v_uid and until > now()),
    'auto_pct',(select auto_pct from app_alliance_members where user_id=v_uid));
end; $$;

/* ---------- Verbände Teil 2b: geteilte Einsätze ----------
   Der Einsatz liegt auf dem Server. Jeder Browser meldet alle 10 s seine Fahrzeuge (sm_sync);
   dabei rechnet der Server alle offenen Einsätze des Verbands weiter (Anforderungen, Löschmittel,
   Patienten) und zählt Fahrzeug-Minuten vor Ort. Abschluss: 10 % Bonus an den Ersteller, Rest nach
   Fahrzeug-Minuten; höchstens 10.000 € je Fahrzeug-Minute (doppelter Spielwert) (Schutz gegen manipulierte Einsatzwerte). */
create table if not exists app_shared_missions (
  id uuid primary key default gen_random_uuid(), alliance_id uuid not null references app_alliances(id) on delete cascade,
  owner uuid references app_users(id) on delete set null, type text not null, code text not null default '', name text not null default '',
  lat double precision not null, lng double precision not null, address text not null default '', spec jsonb not null default '{}',
  reward bigint not null default 0, progress numeric not null default 0, status text not null default 'open',
  patients jsonb not null default '[]', missing jsonb not null default '[]', payout jsonb,
  created_at timestamptz not null default now(), ticked_at timestamptz not null default now(), done_at timestamptz );
create index if not exists app_shared_missions_a on app_shared_missions(alliance_id, status);
create table if not exists app_shared_units (
  mission_id uuid not null references app_shared_missions(id) on delete cascade, user_id uuid not null references app_users(id) on delete cascade,
  vid text not null, vtype text not null, name text not null default '', status int not null default 3,
  lat double precision, lng double precision, water numeric not null default 0, foam numeric not null default 0,
  vmin numeric not null default 0, updated_at timestamptz not null default now(), primary key (mission_id, user_id, vid) );
alter table app_shared_missions enable row level security; alter table app_shared_units enable row level security;
revoke all on app_shared_missions, app_shared_units from anon, authenticated;

create or replace function _sm_tick(p_mid uuid) returns void language plpgsql security definer set search_path=public, extensions as $$
declare
  m app_shared_missions; dt numeric; n int; sw numeric; sf numeric; nw numeric; nf numeric; cov numeric; ok boolean := true;
  r jsonb; have int; need int; used text[] := '{}'; k text; v_miss jsonb := '[]'; rd boolean; eff numeric; st text;
  pats jsonb := '[]'; p jsonb; carriers text[]; taken text[] := '{}'; ntaken text[] := '{}'; unit record; ndone int := 0; npat int := 0;
  c_cap constant numeric := 10000; total numeric; bonus numeric; rest numeric; sumv numeric; v_pay jsonb := '[]'; g record;
begin
  select * into m from app_shared_missions where id=p_mid for update;
  if m.id is null or m.status='done' then return; end if;
  dt := least(1440, greatest(0, extract(epoch from now()-m.ticked_at)/60));
  update app_shared_units set vmin=vmin+dt where mission_id=p_mid and status in (4,5);
  select count(*), coalesce(sum(water),0), coalesce(sum(foam),0) into n, sw, sf from app_shared_units where mission_id=p_mid and status in (4,5);
  rd := coalesce((m.spec->>'rd')::boolean,false);
  -- Anforderungen (gierig, spezifische Gruppen zuerst – wie im Spiel)
  for r in select value from jsonb_array_elements(case when jsonb_typeof(m.spec->'req')='array' then m.spec->'req' else '[]'::jsonb end) order by jsonb_array_length(coalesce(value->'types','[]')) loop
    have := 0; need := greatest(1, coalesce((r->>'count')::int,1));
    for k in select user_id::text||'/'||vid from app_shared_units where mission_id=p_mid and status in (4,5)
        and vtype in (select jsonb_array_elements_text(coalesce(r->'types','[]'))) loop
      exit when have >= need;
      if not (k = any(used)) then used := used || k; have := have + 1; end if;
    end loop;
    if have < need then ok := false; v_miss := v_miss || jsonb_build_object('label',coalesce(r->>'label','Fahrzeug'),'missing',need-have); end if;
  end loop;
  if jsonb_array_length(case when jsonb_typeof(m.spec->'req')='array' then m.spec->'req' else '[]'::jsonb end)=0 and n < coalesce((m.spec->>'minVehicles')::int,1) then
    ok := false; v_miss := v_miss || jsonb_build_object('label','Fahrzeuge','missing',coalesce((m.spec->>'minVehicles')::int,1)-n); end if;
  nw := coalesce((m.spec->'need'->>'water')::numeric,0); nf := coalesce((m.spec->'need'->>'foam')::numeric,0);
  cov := least(case when nw>0 then least(1,sw/nw) else 1 end, case when nf>0 then least(1,sf/nf) else 1 end);
  st := m.status;
  if not rd then
    if ok and n>0 and m.progress < 1 then
      eff := greatest(0.5, coalesce((m.spec->>'minutes')::numeric,10) * (1 - 0.25*(least(n,2)-1)));
      m.progress := least(cov, m.progress + dt/eff); st := 'working';
    elsif m.progress >= 1 then st := 'working';
    elsif n>0 then st := 'waiting'; else st := 'open'; end if;
  end if;
  -- Patienten: Träger (RTW usw.) und Notarzt (NEF/STEMO) vor Ort zuweisen, Behandlung herunterzählen
  carriers := array(select jsonb_array_elements_text(coalesce(m.spec->'carriers','["rtw","nktw","itw"]'::jsonb)));
  for p in select value from jsonb_array_elements(m.patients) loop          -- 1) verlorene Zuweisungen lösen, belegte merken
    if p->>'state' in ('treating','ready') and not exists(select 1 from app_shared_units where mission_id=p_mid and user_id::text||'/'||vid = p->>'rtw' and status in (4,5)) then
      p := p || jsonb_build_object('state','waiting','rtw',null,'treat',6);
    end if;
    if p->>'nef' is not null and p->>'state' not in ('transport','done') and not exists(select 1 from app_shared_units where mission_id=p_mid and user_id::text||'/'||vid = p->>'nef' and status in (4,5)) then
      p := p || jsonb_build_object('nef',null);
    end if;
    if p->>'state' not in ('done','transport') then
      if p->>'rtw' is not null then taken := taken || (p->>'rtw'); end if;
      if p->>'nef' is not null then ntaken := ntaken || (p->>'nef'); end if;
    end if;
    pats := pats || jsonb_build_array(p);
  end loop;
  m.patients := '[]';
  for p in select value from jsonb_array_elements(pats) loop                 -- 2) zuweisen und behandeln
    if p->>'state'='waiting' then
      select user_id::text||'/'||vid as k, user_id into unit from app_shared_units where mission_id=p_mid and status=4 and vtype = any(carriers)
        and not (user_id::text||'/'||vid = any(taken)) and (vtype<>'nktw' or not coalesce((p->>'na')::boolean,false)) order by updated_at limit 1;
      if unit.k is not null then taken := taken || unit.k; p := p || jsonb_build_object('state','treating','rtw',unit.k,'treat',coalesce((p->>'treat')::numeric,6)); end if;
    end if;
    if coalesce((p->>'na')::boolean,false) and p->>'nef' is null and p->>'state' in ('waiting','treating') then
      select user_id::text||'/'||vid as k into unit from app_shared_units where mission_id=p_mid and status in (4,5) and vtype in ('nef','stemo')
        and not (user_id::text||'/'||vid = any(ntaken)) order by updated_at limit 1;
      if unit.k is not null then ntaken := ntaken || unit.k; p := p || jsonb_build_object('nef',unit.k); end if;
    end if;
    if p->>'state'='treating' and (not coalesce((p->>'na')::boolean,false) or p->>'nef' is not null) then
      p := p || jsonb_build_object('treat', coalesce((p->>'treat')::numeric,6) - dt);
      if (p->>'treat')::numeric <= 0 then p := p || jsonb_build_object('state','ready'); end if;
    end if;
    npat := npat + 1; if p->>'state'='done' then ndone := ndone + 1; end if;
    m.patients := m.patients || jsonb_build_array(p);
  end loop;
  if rd then m.progress := case when npat>0 then ndone::numeric/npat else 0 end;
    st := case when exists(select 1 from app_shared_units where mission_id=p_mid and status in (4,5)) or ndone>0 then 'working' else 'open' end; end if;
  -- Abschluss und Auszahlung
  if ndone = npat and (rd or m.progress >= 1) then
    select coalesce(sum(vmin),0) into sumv from app_shared_units where mission_id=p_mid;
    total := floor(least(m.reward, sumv*c_cap));
    bonus := case when m.owner is not null and total > 0 then floor(total*0.1) else 0 end; rest := total - bonus;
    for g in select user_id, sum(vmin) as v from app_shared_units where mission_id=p_mid group by user_id having sum(vmin) > 0 loop
      insert into app_grants(user_id, amount, note) values (g.user_id, floor(rest*g.v/sumv) + case when g.user_id=m.owner then bonus else 0 end, 'Verbandseinsatz: '||m.name);
      v_pay := v_pay || jsonb_build_object('user',g.user_id,'amount',floor(rest*g.v/sumv) + case when g.user_id=m.owner then bonus else 0 end,'vmin',round(g.v,1));
    end loop;
    if bonus > 0 and not exists(select 1 from app_shared_units where mission_id=p_mid and user_id=m.owner and vmin>0) then
      insert into app_grants(user_id, amount, note) values (m.owner, bonus, 'Bonus für geteilten Einsatz: '||m.name);
      v_pay := v_pay || jsonb_build_object('user',m.owner,'amount',bonus,'vmin',0);
    end if;
    update app_shared_missions set status='done', progress=1, patients=m.patients, missing='[]', payout=v_pay, done_at=now(), ticked_at=now() where id=p_mid;
    return;
  end if;
  update app_shared_missions set progress=m.progress, status=st, patients=m.patients, missing=v_miss, ticked_at=now() where id=p_mid;
end; $$;

-- Einsatz freigeben: p {type, code, name, lat, lng, address, spec, reward, patients, progress, units:[...]}
create or replace function sm_share(p_token uuid, p jsonb)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); v_id uuid; v_pats jsonb := '[]'; x jsonb;
begin
  if v_aid is null then return json_build_object('error','Kein Verband'); end if;
  if (select count(*) from app_shared_missions where owner=v_uid and status<>'done') >= 50 then return json_build_object('error','Höchstens 50 geteilte Einsätze gleichzeitig'); end if;
  for x in select value from jsonb_array_elements(case when jsonb_typeof(p->'patients')='array' then p->'patients' else '[]'::jsonb end) limit 20 loop
    v_pats := v_pats || jsonb_build_array(jsonb_build_object('id',left(coalesce(x->>'id',''),40),'na',coalesce((x->>'na')::boolean,false),'dept',left(coalesce(x->>'dept','inn'),8),
      'state',case when x->>'state' in ('transport','done') then 'done' else 'waiting' end,'rtw',null,'nef',null,'treat',greatest(0,least(60,coalesce((x->>'treat')::numeric,6))))); end loop;
  insert into app_shared_missions(alliance_id, owner, type, code, name, lat, lng, address, spec, reward, progress, patients)
    values (v_aid, v_uid, left(coalesce(p->>'type',''),40), left(coalesce(p->>'code',''),20), left(coalesce(p->>'name',''),80),
      (p->>'lat')::double precision, (p->>'lng')::double precision, left(coalesce(p->>'address',''),80), coalesce(p->'spec','{}'),
      greatest(0,least(50000000,coalesce((p->>'reward')::bigint,0))), greatest(0,least(0.99,coalesce((p->>'progress')::numeric,0))), v_pats)
    returning id into v_id;
  insert into app_alliance_radio(alliance_id, user_id, vehicle, status, note) values (v_aid, v_uid, 'Leitstelle', null, 'Einsatz freigegeben: '||left(coalesce(p->>'code',''),20)||' '||left(coalesce(p->>'name',''),80));
  return json_build_object('ok',true,'id',v_id);
end; $$;

-- Abgleich (alle 10 s): eigene Fahrzeuge melden, Patienten-Ereignisse, alle Einsätze weiterrechnen, Liste zurück
create or replace function sm_sync(p_token uuid, p_units jsonb, p_events jsonb)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); x jsonb; v_mid uuid; v_list jsonb := '[]'; mm record; v_veh jsonb;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  if v_aid is null then return json_build_object('ok',true,'missions','[]'::json); end if;
  -- erst bis jetzt weiterrechnen (mit dem bisherigen Stand), dann neue Meldungen übernehmen
  for mm in select id from app_shared_missions where alliance_id=v_aid and status<>'done' loop perform _sm_tick(mm.id); end loop;
  select _jarr(data,'vehicles') into v_veh from app_saves where user_id=v_uid;
  -- eigene Fahrzeuge: gemeldete aktualisieren, nicht mehr gemeldete gelten als abgerückt (Fahrzeug-Minuten bleiben).
  -- Wer offline ist, meldet nichts: seine Fahrzeuge bleiben vor Ort und zählen weiter.
  update app_shared_units u set status=0, updated_at=now() where u.user_id=v_uid and u.status<>0
    and not exists(select 1 from jsonb_array_elements(case when jsonb_typeof(p_units)='array' then p_units else '[]'::jsonb end) e where e->>'mid'=u.mission_id::text and e->>'vid'=u.vid);
  for x in select value from jsonb_array_elements(case when jsonb_typeof(p_units)='array' then p_units else '[]'::jsonb end) limit 200 loop
    begin v_mid := (x->>'mid')::uuid; exception when others then continue; end;
    if not exists(select 1 from app_shared_missions where id=v_mid and alliance_id=v_aid and status<>'done') then continue; end if;
    -- nur Fahrzeuge aus dem eigenen Spielstand, jedes nur in einem Einsatz
    if not exists(select 1 from jsonb_array_elements(coalesce(v_veh,'[]')) v where v->>'id'=x->>'vid' and v->>'type'=x->>'type') then continue; end if;
    update app_shared_units set status=0, updated_at=now() where user_id=v_uid and vid=x->>'vid' and mission_id<>v_mid and status<>0;
    insert into app_shared_units(mission_id, user_id, vid, vtype, name, status, lat, lng, water, foam, updated_at)
      values (v_mid, v_uid, left(x->>'vid',40), left(coalesce(x->>'type',''),30), left(coalesce(x->>'name',''),60),
        case when (x->>'status') ~ '^[345]$' then (x->>'status')::int else 3 end, (x->>'lat')::double precision, (x->>'lng')::double precision,
        greatest(0,least(20000,coalesce((x->>'water')::numeric,0))), greatest(0,least(20000,coalesce((x->>'foam')::numeric,0))), now())
      on conflict (mission_id,user_id,vid) do update set status=excluded.status, lat=excluded.lat, lng=excluded.lng, water=excluded.water, foam=excluded.foam, vtype=excluded.vtype, name=excluded.name, updated_at=now();
  end loop;
  -- Patienten-Ereignisse vom Besitzer des RTW: transport (ab ready) und done (ab transport)
  for x in select value from jsonb_array_elements(case when jsonb_typeof(p_events)='array' then p_events else '[]'::jsonb end) limit 50 loop
    begin v_mid := (x->>'mid')::uuid; exception when others then continue; end;
    update app_shared_missions s set patients=(select jsonb_agg(case when q->>'id'=x->>'pid' and split_part(coalesce(q->>'rtw',q->>'by',''),'/',1)=v_uid::text
          and ((x->>'state'='transport' and q->>'state'='ready') or (x->>'state'='done' and q->>'state'='transport'))
        then q || jsonb_build_object('state',x->>'state','by',coalesce(q->>'rtw',q->>'by')) else q end) from jsonb_array_elements(s.patients) q)
      where s.id=v_mid and s.alliance_id=v_aid and s.status<>'done';
  end loop;
  for mm in select id from app_shared_missions where alliance_id=v_aid and status<>'done' loop perform _sm_tick(mm.id); end loop;
  delete from app_shared_missions where alliance_id=v_aid and ((status='done' and done_at < now()-interval '10 minutes')
    or (status<>'done' and created_at < now()-interval '48 hours'));
  select coalesce(jsonb_agg(jsonb_build_object('id',s.id,'owner',ou.username,'mine',s.owner=v_uid,'type',s.type,'code',s.code,'name',s.name,'lat',s.lat,'lng',s.lng,'address',s.address,
      'status',s.status,'progress',round(s.progress,4),'reward',s.reward,'missing',s.missing,'created_at',s.created_at,
      'payout',case when s.status='done' then (select jsonb_agg(jsonb_build_object('name',pu.username,'amount',(e->>'amount')::bigint,'vmin',e->'vmin','mine',(e->>'user')=v_uid::text)) from jsonb_array_elements(coalesce(s.payout,'[]')) e left join app_users pu on pu.id=(e->>'user')::uuid) end,
      'patients',(select coalesce(jsonb_agg(q || jsonb_build_object('mine',split_part(coalesce(q->>'rtw',q->>'by',''),'/',1)=v_uid::text,'rtw_vid',split_part(coalesce(q->>'rtw',q->>'by',''),'/',2),
          'rtw_owner',(select username from app_users where id::text=split_part(coalesce(q->>'rtw',q->>'by',''),'/',1)),
          'nef_mine',split_part(coalesce(q->>'nef',''),'/',1)=v_uid::text,'nef_vid',nullif(split_part(coalesce(q->>'nef',''),'/',2),''))),'[]') from jsonb_array_elements(s.patients) q),
      'units',(select coalesce(jsonb_agg(jsonb_build_object('vid',u.vid,'type',u.vtype,'name',u.name,'status',u.status,'lat',u.lat,'lng',u.lng,'water',u.water,'foam',u.foam,'vmin',round(u.vmin,1),'player',uu.username,'mine',u.user_id=v_uid) order by u.status desc),'[]')
          from app_shared_units u join app_users uu on uu.id=u.user_id where u.mission_id=s.id and (u.status<>0 or u.vmin>0)))
    order by s.created_at), '[]') into v_list
  from app_shared_missions s left join app_users ou on ou.id=s.owner where s.alliance_id=v_aid;
  return json_build_object('ok',true,'missions',v_list);
end; $$;

/* ---------- Verbände Teil 3: News, Regeln, Forum, Akademie-Freigabe, Verbandsgebäude ----------
   News und Regeln schreibt, wer „Moderieren“ hat. Forum: alle Mitglieder (Timeout sperrt auch das Forum).
   Akademien: Besitzer gibt sie im Spielstand frei (buildings[].allyShare = {limit}); Mitglieder buchen einen
   Lehrsaal für eigene Leute (höchstens limit Personen gleichzeitig je Mitglied).
   Verbandsgebäude werden aus der Verbandskasse gebaut (Recht „Finanzen“): Krankenhaus und Akademie. */
alter table app_alliances add column if not exists rules text not null default '';
alter table app_alliances add column if not exists academy_limit int not null default 10;
create table if not exists app_alliance_news (
  id bigserial primary key, alliance_id uuid not null references app_alliances(id) on delete cascade, user_id uuid references app_users(id) on delete set null,
  title text not null, body text not null default '', created_at timestamptz not null default now() );
create index if not exists app_alliance_news_a on app_alliance_news(alliance_id, id desc);
create table if not exists app_alliance_threads (
  id bigserial primary key, alliance_id uuid not null references app_alliances(id) on delete cascade, user_id uuid references app_users(id) on delete set null,
  title text not null, pinned boolean not null default false, locked boolean not null default false,
  created_at timestamptz not null default now(), last_at timestamptz not null default now() );
create index if not exists app_alliance_threads_a on app_alliance_threads(alliance_id, last_at desc);
create table if not exists app_alliance_posts (
  id bigserial primary key, thread_id bigint not null references app_alliance_threads(id) on delete cascade, user_id uuid references app_users(id) on delete set null,
  body text not null, deleted boolean not null default false, created_at timestamptz not null default now() );
create index if not exists app_alliance_posts_t on app_alliance_posts(thread_id, id);
create table if not exists app_alliance_buildings (
  id uuid primary key default gen_random_uuid(), alliance_id uuid not null references app_alliances(id) on delete cascade,
  type text not null, name text not null, lat double precision not null, lng double precision not null, rooms int not null default 1,
  created_at timestamptz not null default now() );
create table if not exists app_academy_bookings (                -- belegte Lehrsäle (fremde Akademie oder Verbandsakademie)
  id uuid primary key default gen_random_uuid(), akey text not null, user_id uuid not null references app_users(id) on delete cascade,
  course text not null, persons int not null, started_at timestamptz not null default now(), ends_at timestamptz not null );
create index if not exists app_academy_bookings_k on app_academy_bookings(akey, ends_at);
alter table app_alliance_news enable row level security; alter table app_alliance_threads enable row level security;
alter table app_alliance_posts enable row level security; alter table app_alliance_buildings enable row level security; alter table app_academy_bookings enable row level security;
revoke all on app_alliance_news, app_alliance_threads, app_alliance_posts, app_alliance_buildings, app_academy_bookings from anon, authenticated;

create or replace function _ally_muted(p_aid uuid, p_uid uuid) returns timestamptz language sql stable security definer set search_path=public, extensions as $$
  select until from app_alliance_timeouts where alliance_id=p_aid and user_id=p_uid and until > now(); $$;

-- Regeln und News
create or replace function ally_board(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null then return json_build_object('error','Kein Verband'); end if;
  return json_build_object('rules',(select rules from app_alliances where id=v_aid), 'can_mod',_ally_perm(v_uid,'moderate'),
    'news',coalesce((select json_agg(x) from (select n.id, n.title, n.body, n.created_at as at, u.username as name from app_alliance_news n
      left join app_users u on u.id=n.user_id where n.alliance_id=v_aid order by n.id desc limit 30) x),'[]'::json));
end; $$;
create or replace function ally_rules_save(p_token uuid, p_rules text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null or not _ally_perm(v_uid,'moderate') then return json_build_object('error','Keine Berechtigung'); end if;
  update app_alliances set rules=left(coalesce(p_rules,''),10000) where id=v_aid;
  return json_build_object('ok',true);
end; $$;
create or replace function ally_news_post(p_token uuid, p_title text, p_body text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null or not _ally_perm(v_uid,'moderate') then return json_build_object('error','Keine Berechtigung'); end if;
  if btrim(coalesce(p_title,''))='' then return json_build_object('error','Titel fehlt'); end if;
  insert into app_alliance_news(alliance_id, user_id, title, body) values (v_aid, v_uid, left(btrim(p_title),120), left(coalesce(p_body,''),5000));
  return json_build_object('ok',true);
end; $$;
create or replace function ally_news_delete(p_token uuid, p_id bigint)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null or not _ally_perm(v_uid,'moderate') then return json_build_object('error','Keine Berechtigung'); end if;
  delete from app_alliance_news where id=p_id and alliance_id=v_aid;
  return json_build_object('ok',true);
end; $$;

-- Forum
create or replace function ally_forum(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null then return json_build_object('error','Kein Verband'); end if;
  return json_build_object('can_mod',_ally_perm(v_uid,'moderate'),'muted_until',_ally_muted(v_aid,v_uid),
    'threads',coalesce((select json_agg(x) from (select t.id, t.title, t.pinned, t.locked, t.created_at, t.last_at, u.username as name,
      (select count(*) from app_alliance_posts p where p.thread_id=t.id and not p.deleted) as posts,
      (select lu.username from app_alliance_posts p left join app_users lu on lu.id=p.user_id where p.thread_id=t.id order by p.id desc limit 1) as last_name
      from app_alliance_threads t left join app_users u on u.id=t.user_id where t.alliance_id=v_aid order by t.pinned desc, t.last_at desc limit 100) x),'[]'::json));
end; $$;
create or replace function ally_forum_thread(p_token uuid, p_id bigint)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); t app_alliance_threads;
begin
  select * into t from app_alliance_threads where id=p_id and alliance_id=v_aid;
  if v_aid is null or t.id is null then return json_build_object('error','Thema nicht gefunden'); end if;
  return json_build_object('thread',json_build_object('id',t.id,'title',t.title,'pinned',t.pinned,'locked',t.locked),
    'posts',coalesce((select json_agg(x) from (select p.id, p.user_id, case when p.deleted then '' else p.body end as body, p.deleted, p.created_at as at,
      u.username as name, p.user_id=v_uid as mine from app_alliance_posts p left join app_users u on u.id=p.user_id where p.thread_id=t.id order by p.id) x),'[]'::json));
end; $$;
-- p_thread null: neues Thema mit p_title
create or replace function ally_forum_post(p_token uuid, p_thread bigint, p_title text, p_body text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); v_until timestamptz; t app_alliance_threads; v_tid bigint;
begin
  if v_aid is null then return json_build_object('error','Kein Verband'); end if;
  v_until := _ally_muted(v_aid,v_uid);
  if v_until is not null then return json_build_object('error','Du bist stummgeschaltet bis '||to_char(v_until at time zone 'Europe/Berlin','DD.MM. HH24:MI')); end if;
  p_body := btrim(coalesce(p_body,'')); if p_body='' then return json_build_object('error','Leerer Beitrag'); end if;
  if (select count(*) from app_alliance_posts where user_id=v_uid and created_at > now()-interval '1 minute') >= 5 then return json_build_object('error','Bitte langsamer schreiben'); end if;
  if p_thread is null then
    if btrim(coalesce(p_title,''))='' then return json_build_object('error','Titel fehlt'); end if;
    if (select count(*) from app_alliance_threads where alliance_id=v_aid) >= 500 then return json_build_object('error','Zu viele Themen – bitte alte löschen'); end if;
    insert into app_alliance_threads(alliance_id, user_id, title) values (v_aid, v_uid, left(btrim(p_title),120)) returning id into v_tid;
  else
    select * into t from app_alliance_threads where id=p_thread and alliance_id=v_aid;
    if t.id is null then return json_build_object('error','Thema nicht gefunden'); end if;
    if t.locked and not _ally_perm(v_uid,'moderate') then return json_build_object('error','Thema ist geschlossen'); end if;
    v_tid := t.id; update app_alliance_threads set last_at=now() where id=v_tid;
  end if;
  insert into app_alliance_posts(thread_id, user_id, body) values (v_tid, v_uid, left(p_body,5000));
  return json_build_object('ok',true,'thread',v_tid);
end; $$;
create or replace function ally_forum_delete(p_token uuid, p_post bigint)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  update app_alliance_posts p set deleted=true from app_alliance_threads t
    where p.id=p_post and t.id=p.thread_id and t.alliance_id=v_aid and (p.user_id=v_uid or _ally_perm(v_uid,'moderate'));
  if not found then return json_build_object('error','Keine Berechtigung'); end if;
  return json_build_object('ok',true);
end; $$;
-- p_action: pin, unpin, lock, unlock, delete
create or replace function ally_forum_mod(p_token uuid, p_thread bigint, p_action text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null or not _ally_perm(v_uid,'moderate') then return json_build_object('error','Keine Berechtigung'); end if;
  if p_action='delete' then delete from app_alliance_threads where id=p_thread and alliance_id=v_aid;
  elsif p_action in ('pin','unpin') then update app_alliance_threads set pinned=(p_action='pin') where id=p_thread and alliance_id=v_aid;
  elsif p_action in ('lock','unlock') then update app_alliance_threads set locked=(p_action='lock') where id=p_thread and alliance_id=v_aid;
  else return json_build_object('error','Unbekannte Aktion'); end if;
  return json_build_object('ok',true);
end; $$;

-- Verbandsgebäude (Kosten: Krankenhaus 3 Mio., Akademie 2,5 Mio., weiterer Lehrsaal 1 Mio., höchstens 4 Säle)
create or replace function ally_building_build(p_token uuid, p_type text, p_name text, p_lat double precision, p_lng double precision)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); v_cost bigint; v_kasse bigint;
begin
  if v_aid is null or not _ally_perm(v_uid,'finance') then return json_build_object('error','Keine Berechtigung'); end if;
  v_cost := case p_type when 'kh' then 3000000 when 'akademie' then 2500000 end;
  if v_cost is null then return json_build_object('error','Unbekannter Gebäudetyp'); end if;
  if p_lat is null or p_lng is null or abs(p_lat)>85 or abs(p_lng)>180 then return json_build_object('error','Ungültiger Ort'); end if;
  if (select count(*) from app_alliance_buildings where alliance_id=v_aid) >= 20 then return json_build_object('error','Höchstens 20 Verbandsgebäude'); end if;
  select kasse into v_kasse from app_alliances where id=v_aid for update;
  if v_kasse < v_cost then return json_build_object('error','Zu wenig in der Verbandskasse ('||v_cost||' € nötig)'); end if;
  update app_alliances set kasse=kasse-v_cost where id=v_aid;
  insert into app_alliance_buildings(alliance_id, type, name, lat, lng, depts)
    values (v_aid, p_type, left(coalesce(nullif(btrim(p_name),''), case p_type when 'kh' then 'Verbandskrankenhaus' else 'Verbandsakademie' end),60), p_lat, p_lng,
      case when p_type='kh' then '[]'::jsonb end);
  insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_aid, v_uid, 'gebaeude', -v_cost,
    case p_type when 'kh' then 'Verbandskrankenhaus' else 'Verbandsakademie' end||' gebaut: '||left(coalesce(p_name,''),60));
  return json_build_object('ok',true,'cost',v_cost);
end; $$;
create or replace function ally_building_expand(p_token uuid, p_id uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); b app_alliance_buildings; v_kasse bigint;
begin
  if v_aid is null or not _ally_perm(v_uid,'finance') then return json_build_object('error','Keine Berechtigung'); end if;
  select * into b from app_alliance_buildings where id=p_id and alliance_id=v_aid for update;
  if b.id is null or b.type<>'akademie' then return json_build_object('error','Gebäude nicht gefunden'); end if;
  if b.rooms >= 4 then return json_build_object('error','Höchstens 4 Lehrsäle'); end if;
  select kasse into v_kasse from app_alliances where id=v_aid for update;
  if v_kasse < 1000000 then return json_build_object('error','Zu wenig in der Verbandskasse (1.000.000 € nötig)'); end if;
  update app_alliances set kasse=kasse-1000000 where id=v_aid;
  update app_alliance_buildings set rooms=rooms+1 where id=p_id;
  insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_aid, v_uid, 'gebaeude', -1000000, 'Lehrsaal für '||b.name);
  return json_build_object('ok',true);
end; $$;
create or replace function ally_building_remove(p_token uuid, p_id uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); v_name text;
begin
  if v_aid is null or not _ally_perm(v_uid,'finance') then return json_build_object('error','Keine Berechtigung'); end if;
  delete from app_alliance_buildings where id=p_id and alliance_id=v_aid returning name into v_name;
  if v_name is null then return json_build_object('error','Gebäude nicht gefunden'); end if;
  insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_aid, v_uid, 'gebaeude', 0, 'abgerissen: '||v_name);
  return json_build_object('ok',true);
end; $$;

-- Verbandslehrgänge (Teil 4): die Lehrgangsleitung schreibt einen Lehrgang in einer Verbandsakademie aus (Kasse zahlt 150.000 €),
-- Mitglieder melden bis zum Start eigenes Personal an (Plätze je Mitglied und Gebühr je Person legt die Lehrgangsleitung fest)
create table if not exists app_ally_courses (
  id uuid primary key default gen_random_uuid(), alliance_id uuid not null references app_alliances(id) on delete cascade,
  building_id uuid not null references app_alliance_buildings(id) on delete cascade, course text not null,
  created_by uuid references app_users(id) on delete set null, per_member int not null, fee bigint not null default 0,
  capacity int not null default 10, starts_at timestamptz not null, ends_at timestamptz not null, created_at timestamptz not null default now() );
create index if not exists app_ally_courses_a on app_ally_courses(alliance_id, ends_at);
create table if not exists app_ally_course_seats (
  course_id uuid not null references app_ally_courses(id) on delete cascade, user_id uuid not null references app_users(id) on delete cascade,
  persons int not null, at timestamptz not null default now(), primary key (course_id, user_id) );
alter table app_ally_courses enable row level security; alter table app_ally_course_seats enable row level security;
revoke all on app_ally_courses, app_ally_course_seats from anon, authenticated;
-- Verbandskrankenhaus: Fachabteilungen als Erweiterungen [{dept, ready_at}], Innere Medizin ist immer dabei (null = Altbestand: alle)
alter table app_alliance_buildings add column if not exists depts jsonb;

-- Akademien im Verband: freigegebene Akademien der Mitglieder (aus dem Spielstand) und Verbandsakademien
create or replace function _ally_academies(p_aid uuid) returns table(akey text, kind text, owner uuid, owner_name text, name text, lat double precision, lng double precision,
  rooms int, own_used int, ext_used int, lim int, dur numeric, cost numeric)
language sql stable security definer set search_path=public, extensions as $$
  with now_ms as (select extract(epoch from now())*1000 as t)
  select 'u:'||m.user_id||':'||(b->>'id'), 'member', m.user_id, u.username, b->>'name', (b->>'lat')::double precision, (b->>'lng')::double precision,
    1 + (select count(*)::int from jsonb_array_elements(coalesce(b->'exts','[]')) e where e->>'key'='saal' and coalesce((e->>'readyAt')::numeric,0) <= (select t from now_ms)),
    (select count(*)::int from jsonb_array_elements(coalesce(b->'courses','[]')) c where coalesce((c->>'startedAt')::numeric,0)+coalesce((c->>'durationMs')::numeric,0) > (select t from now_ms)),
    (select count(*)::int from app_academy_bookings k where k.akey='u:'||m.user_id||':'||(b->>'id') and k.ends_at > now()),
    greatest(1,least(10,coalesce((b->'allyShare'->>'limit')::int,10))),
    case when exists(select 1 from jsonb_array_elements(coalesce(b->'exts','[]')) e where e->>'key'='sim' and coalesce((e->>'readyAt')::numeric,0) <= (select t from now_ms)) then 0.75 else 1 end,
    case when exists(select 1 from jsonb_array_elements(coalesce(b->'exts','[]')) e where e->>'key'='hof' and coalesce((e->>'readyAt')::numeric,0) <= (select t from now_ms)) then 0.7 else 1 end
  from app_alliance_members m join app_users u on u.id=m.user_id join app_saves s on s.user_id=m.user_id, jsonb_array_elements(_jarr(s.data,'buildings')) b
  where m.alliance_id=p_aid and b->>'typeId'='academy' and jsonb_typeof(b->'allyShare')='object'
    and coalesce((b->>'readyAt')::numeric,0) <= (select t from now_ms)
  union all
  select 'a:'||ab.id, 'alliance', null, null, ab.name, ab.lat, ab.lng, ab.rooms, 0,
    (select count(*)::int from app_ally_courses c where c.building_id=ab.id and c.ends_at > now()), 10, 1, 1
  from app_alliance_buildings ab join app_alliances al on al.id=ab.alliance_id where ab.alliance_id=p_aid and ab.type='akademie'; $$;

-- Gebäude und Akademien des Verbands (Karte, Krankenhausliste, Reiter Akademien/Gebäude)
create or replace function ally_assets(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null then return json_build_object('buildings','[]'::json,'academies','[]'::json); end if;
  return json_build_object('can_build',_ally_perm(v_uid,'finance'),'kasse',(select kasse from app_alliances where id=v_aid),'academy_limit',(select academy_limit from app_alliances where id=v_aid),
    'buildings',coalesce((select json_agg(json_build_object('id',id,'type',type,'name',name,'lat',lat,'lng',lng,'rooms',rooms,
        'depts',case when type<>'kh' then null when depts is null then '["inn","unf","kar","str","geb","kin","psy","bra"]'::jsonb
          else '["inn"]'::jsonb || coalesce((select jsonb_agg(d->'dept') from jsonb_array_elements(depts) d where (d->>'ready_at')::timestamptz <= now()),'[]') end,
        'building',case when type='kh' and depts is not null then (select jsonb_agg(jsonb_build_object('dept',d->'dept','ready_at',d->'ready_at')) from jsonb_array_elements(depts) d where (d->>'ready_at')::timestamptz > now()) end)
      order by created_at) from app_alliance_buildings where alliance_id=v_aid),'[]'::json),
    'academies',coalesce((select json_agg(json_build_object('key',a.akey,'kind',a.kind,'owner',a.owner_name,'mine',a.owner=v_uid,'name',a.name,'lat',a.lat,'lng',a.lng,
        'rooms',a.rooms,'used',a.own_used+a.ext_used,'ext_used',a.ext_used,'limit',a.lim,'dur',a.dur,'cost',a.cost,
        'my_persons',(select coalesce(sum(persons),0) from app_academy_bookings k where k.akey=a.akey and k.user_id=v_uid and k.ends_at > now()),
        'bookings',(select coalesce(json_agg(json_build_object('name',bu.username,'course',k.course,'persons',k.persons,'ends_at',k.ends_at) order by k.ends_at),'[]'::json)
          from app_academy_bookings k join app_users bu on bu.id=k.user_id where k.akey=a.akey and k.ends_at > now()))) from _ally_academies(v_aid) a),'[]'::json));
end; $$;

-- Lehrsaal buchen: p_duration = Grunddauer des Lehrgangs (ms), wird auf 3–7 Tage begrenzt; Verbandsakademie kostet 150.000 € (in die Kasse)
create or replace function ally_course_book(p_token uuid, p_key text, p_course text, p_persons int, p_duration bigint)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); a record; v_mine int; v_ms bigint; v_id uuid; v_cost bigint := 0;
begin
  if v_aid is null then return json_build_object('error','Kein Verband'); end if;
  select * into a from _ally_academies(v_aid) x where x.akey=p_key;
  if a.akey is null then return json_build_object('error','Akademie nicht (mehr) freigegeben'); end if;
  if a.owner=v_uid then return json_build_object('error','Eigene Akademie: Lehrgang direkt dort starten'); end if;
  perform pg_advisory_xact_lock(hashtext(p_key));
  if (select count(*) from app_academy_bookings k where k.akey=p_key and k.ends_at > now()) + a.own_used >= a.rooms then return json_build_object('error','Alle Lehrsäle belegt'); end if;
  if coalesce(p_persons,0) < 1 or p_persons > 10 then return json_build_object('error','1 bis 10 Personen je Lehrsaal'); end if;
  select coalesce(sum(persons),0) into v_mine from app_academy_bookings where akey=p_key and user_id=v_uid and ends_at > now();
  if v_mine + p_persons > a.lim then return json_build_object('error','Limit: höchstens '||a.lim||' Personen gleichzeitig (noch '||greatest(0,a.lim-v_mine)||')'); end if;
  v_ms := round(greatest(259200000, least(604800000, coalesce(p_duration,604800000))) * a.dur);
  if a.kind='alliance' then return json_build_object('error','In der Verbandsakademie schreibt die Lehrgangsleitung Lehrgänge aus – dort anmelden'); end if;
  insert into app_academy_bookings(akey, user_id, course, persons, ends_at) values (p_key, v_uid, left(coalesce(p_course,''),40), p_persons, now()+make_interval(secs=>v_ms/1000.0))
    returning id into v_id;
  return json_build_object('ok',true,'id',v_id,'duration_ms',v_ms,'paid',v_cost,'cost_factor',a.cost);
end; $$;

/* ---------- Codes (Belohnungen über Socials) ----------
   Spieler lösen Codes einmalig ein (code_redeem). Belohnungen: money, staff (mit optionaler Ausbildung),
   building (Gutschein für Feuerwache/Akademie/Leitstelle), extension (Gutschein für eine Erweiterung).
   Geld und der Wert gratis gebauter Wachen/Akademien werden dem Anti-Cheat als erlaubter Zuwachs gutgeschrieben.
   Admin: eigenes Passwort (nur bcrypt-Hash in der DB). Setzen NUR im Supabase-SQL-Editor:
     select admin_set_password('ein langes Passwort');
   Die Funktion ist für die Website (anon) gesperrt. Login: 5 Fehlversuche je IP bzw. 20 insgesamt in 15 min sperren,
   Admin-Sitzung gilt 2 Stunden. */
create table if not exists app_admin ( id int primary key check (id=1), pw_hash text not null, updated_at timestamptz not null default now() );
create table if not exists app_admin_sessions ( token_hash text primary key, expires_at timestamptz not null, ip text, created_at timestamptz not null default now() );
create table if not exists app_admin_attempts ( id bigserial primary key, ip text, ok boolean not null, at timestamptz not null default now() );
create table if not exists app_codes (
  code text primary key, rewards jsonb not null default '[]', note text not null default '',
  expires_at timestamptz, max_uses int, new_days int, active boolean not null default true,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now() );
create table if not exists app_code_redemptions (
  code text not null references app_codes(code) on delete cascade, user_id uuid not null references app_users(id) on delete cascade,
  at timestamptz not null default now(), primary key (code, user_id) );
create table if not exists app_code_attempts ( user_id uuid not null references app_users(id) on delete cascade, at timestamptz not null default now() );
create index if not exists app_code_attempts_u on app_code_attempts(user_id, at);
alter table app_admin enable row level security; alter table app_admin_sessions enable row level security; alter table app_admin_attempts enable row level security;
alter table app_codes enable row level security; alter table app_code_redemptions enable row level security; alter table app_code_attempts enable row level security;
revoke all on app_admin, app_admin_sessions, app_admin_attempts, app_codes, app_code_redemptions, app_code_attempts from anon, authenticated;

create or replace function admin_set_password(p_password text) returns text language plpgsql security definer set search_path=public, extensions as $$
begin
  if length(coalesce(p_password,'')) < 12 then raise exception 'Passwort muss mindestens 12 Zeichen haben'; end if;
  insert into app_admin(id, pw_hash) values (1, crypt(p_password, gen_salt('bf', 10)))
    on conflict (id) do update set pw_hash=excluded.pw_hash, updated_at=now();
  delete from app_admin_sessions;                                      -- alle Admin-Sitzungen beenden
  return 'Admin-Passwort gesetzt';
end; $$;

create or replace function _admin_ok(p_token uuid) returns boolean language sql security definer set search_path=public, extensions as $$
  select p_token is not null and exists(select 1 from app_admin_sessions where token_hash=_token_hash(p_token) and expires_at > now()); $$;

create or replace function admin_login(p_password text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_ip text := coalesce(_client_ip(),'?'); v_hash text; v_tok uuid;
begin
  delete from app_admin_attempts where at < now()-interval '1 day';
  delete from app_admin_sessions where expires_at < now();
  if (select count(*) from app_admin_attempts where not ok and ip=v_ip and at > now()-interval '15 minutes') >= 5
     or (select count(*) from app_admin_attempts where not ok and at > now()-interval '15 minutes') >= 20 then
    return json_build_object('error','Zu viele Fehlversuche. Bitte 15 Minuten warten.'); end if;
  select pw_hash into v_hash from app_admin where id=1;
  if v_hash is null or p_password is null or crypt(p_password, v_hash) <> v_hash then
    perform pg_sleep(0.5);
    insert into app_admin_attempts(ip, ok) values (v_ip, false);
    return json_build_object('error','Falsches Passwort'); end if;
  insert into app_admin_attempts(ip, ok) values (v_ip, true);
  v_tok := gen_random_uuid();
  insert into app_admin_sessions(token_hash, expires_at, ip) values (_token_hash(v_tok), now()+interval '2 hours', v_ip);
  return json_build_object('ok',true,'token',v_tok,'expires_at',now()+interval '2 hours');
end; $$;
create or replace function admin_logout(p_token uuid) returns json language sql security definer set search_path=public, extensions as $$
  delete from app_admin_sessions where token_hash=_token_hash(p_token); select json_build_object('ok',true); $$;

-- Belohnungen prüfen und vereinheitlichen
create or replace function _code_rewards(p jsonb) returns jsonb language plpgsql immutable set search_path=public, extensions as $$
declare r jsonb; out jsonb := '[]'; n int;
begin
  if jsonb_typeof(p) <> 'array' or jsonb_array_length(p)=0 then raise exception 'Mindestens eine Belohnung'; end if;
  if jsonb_array_length(p) > 10 then raise exception 'Höchstens 10 Belohnungen je Code'; end if;
  for r in select value from jsonb_array_elements(p) loop
    case r->>'type'
      when 'money' then n := (r->>'amount')::int;
        if n is null or n < 1 or n > 100000000 then raise exception 'Geld: 1 bis 100.000.000 €'; end if;
        out := out || jsonb_build_array(jsonb_build_object('type','money','amount',n));
      when 'staff' then n := (r->>'count')::int;
        if n is null or n < 1 or n > 50 then raise exception 'Personal: 1 bis 50 Personen'; end if;
        if coalesce(r->>'qual','') !~ '^[A-Za-z0-9_-]{0,40}$' then raise exception 'Ungültige Ausbildung'; end if;
        out := out || jsonb_build_array(jsonb_build_object('type','staff','count',n,'qual',nullif(r->>'qual','')));
      when 'building' then n := coalesce((r->>'count')::int,1);
        if r->>'building' not in ('fire','academy','leitstelle') then raise exception 'Unbekanntes Gebäude'; end if;
        if n < 1 or n > 5 then raise exception 'Gebäude: 1 bis 5'; end if;
        out := out || jsonb_build_array(jsonb_build_object('type','building','building',r->>'building','count',n));
      when 'extension' then n := coalesce((r->>'count')::int,1);
        if coalesce(r->>'ext','') !~ '^[a-z]{1,20}$' then raise exception 'Unbekannte Erweiterung'; end if;
        if n < 1 or n > 10 then raise exception 'Erweiterung: 1 bis 10'; end if;
        out := out || jsonb_build_array(jsonb_build_object('type','extension','ext',r->>'ext','count',n));
      else raise exception 'Unbekannte Belohnung: %', r->>'type';
    end case;
  end loop;
  return out;
end; $$;

create or replace function admin_codes(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
begin
  if not _admin_ok(p_token) then return json_build_object('error','Nicht angemeldet'); end if;
  return json_build_object('ok',true,'codes',coalesce((select json_agg(json_build_object('code',c.code,'rewards',c.rewards,'note',c.note,'expires_at',c.expires_at,
      'max_uses',c.max_uses,'new_days',c.new_days,'active',c.active,'premium_only',c.premium_only,'created_at',c.created_at,
      'uses',(select count(*) from app_code_redemptions r where r.code=c.code)) order by c.created_at desc) from app_codes c),'[]'::json));
end; $$;
-- Anlegen oder ändern: p {code, rewards, note, expires_at, max_uses, new_days, active}
create or replace function admin_code_save(p_token uuid, p jsonb)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_code text := upper(btrim(coalesce(p->>'code',''))); v_rw jsonb;
begin
  if not _admin_ok(p_token) then return json_build_object('error','Nicht angemeldet'); end if;
  if v_code !~ '^[A-Z0-9_-]{3,32}$' then return json_build_object('error','Code: 3–32 Zeichen, nur A–Z, 0–9, - und _'); end if;
  begin v_rw := _code_rewards(p->'rewards'); exception when others then return json_build_object('error',sqlerrm); end;
  insert into app_codes(code, rewards, note, expires_at, max_uses, new_days, active, premium_only)
    values (v_code, v_rw, left(coalesce(p->>'note',''),200), nullif(p->>'expires_at','')::timestamptz,
      nullif(greatest(0,coalesce((p->>'max_uses')::int,0)),0), nullif(greatest(0,coalesce((p->>'new_days')::int,0)),0), coalesce((p->>'active')::boolean,true),
      coalesce((p->>'premium_only')::boolean,false))
    on conflict (code) do update set rewards=excluded.rewards, note=excluded.note, expires_at=excluded.expires_at, max_uses=excluded.max_uses,
      new_days=excluded.new_days, active=excluded.active, premium_only=excluded.premium_only, updated_at=now();
  return json_build_object('ok',true,'code',v_code);
end; $$;
create or replace function admin_code_active(p_token uuid, p_code text, p_active boolean)
returns json language plpgsql security definer set search_path=public, extensions as $$
begin
  if not _admin_ok(p_token) then return json_build_object('error','Nicht angemeldet'); end if;
  update app_codes set active=p_active, updated_at=now() where code=upper(p_code);
  return json_build_object('ok',found);
end; $$;
create or replace function admin_code_delete(p_token uuid, p_code text)
returns json language plpgsql security definer set search_path=public, extensions as $$
begin
  if not _admin_ok(p_token) then return json_build_object('error','Nicht angemeldet'); end if;
  delete from app_codes where code=upper(p_code);
  return json_build_object('ok',found);
end; $$;
create or replace function admin_code_redemptions(p_token uuid, p_code text)
returns json language plpgsql security definer set search_path=public, extensions as $$
begin
  if not _admin_ok(p_token) then return json_build_object('error','Nicht angemeldet'); end if;
  return json_build_object('ok',true,'list',coalesce((select json_agg(json_build_object('name',u.username,'at',r.at) order by r.at desc)
    from app_code_redemptions r join app_users u on u.id=r.user_id where r.code=upper(p_code)),'[]'::json));
end; $$;

-- Einlösen (Spieler): Geld + Wert gratis gebauter Wachen/Akademien gehen als erlaubter Zuwachs an den Anti-Cheat
create or replace function code_redeem(p_token uuid, p_code text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); c app_codes; v_created timestamptz; v_value numeric := 0; r jsonb;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  delete from app_code_attempts where at < now()-interval '1 hour';
  if (select count(*) from app_code_attempts where user_id=v_uid and at > now()-interval '10 minutes') >= 10 then
    return json_build_object('error','Zu viele ungültige Codes. Bitte 10 Minuten warten.'); end if;
  select * into c from app_codes where code=upper(btrim(coalesce(p_code,''))) for update;
  if c.code is null or not c.active then insert into app_code_attempts(user_id) values (v_uid); return json_build_object('error','Code ungültig'); end if;
  if c.premium_only and not _premium(v_uid) then return json_build_object('error','Dieser Code ist nur für Premium-Spieler'); end if;
  if c.expires_at is not null and c.expires_at < now() then return json_build_object('error','Code ist abgelaufen'); end if;
  if exists(select 1 from app_code_redemptions where code=c.code and user_id=v_uid) then return json_build_object('error','Code bereits eingelöst'); end if;
  if c.max_uses is not null and (select count(*) from app_code_redemptions where code=c.code) >= c.max_uses then return json_build_object('error','Code ist bereits vergeben'); end if;
  if c.new_days is not null then
    select created_at into v_created from app_users where id=v_uid;
    if v_created < now() - make_interval(days=>c.new_days) then return json_build_object('error','Code gilt nur für neue Spieler (Konto jünger als '||c.new_days||' Tage)'); end if; end if;
  for r in select value from jsonb_array_elements(c.rewards) loop
    if r->>'type'='money' then v_value := v_value + (r->>'amount')::numeric;
    elsif r->>'type'='building' and r->>'building'='fire' then v_value := v_value + coalesce((select price from app_prices where kind='station' and id='L1'),0)*(r->>'count')::int;
    elsif r->>'type'='building' and r->>'building'='academy' then v_value := v_value + coalesce((select price from app_prices where kind='academy' and id='L1'),0)*(r->>'count')::int;
    end if;
  end loop;
  update app_saves set econ_adjust=coalesce(econ_adjust,0)+v_value where user_id=v_uid and jsonb_typeof(data)='object';
  if not found then return json_build_object('error','Spielstand noch nicht gespeichert – bitte kurz warten und erneut versuchen'); end if;
  insert into app_code_redemptions(code, user_id) values (c.code, v_uid);
  return json_build_object('ok',true,'code',c.code,'rewards',c.rewards);
end; $$;

/* ---------- Verbände Teil 4: Verbandslehrgänge, Fachabteilungen im Verbandskrankenhaus ---------- */
create or replace function ally_courses(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid);
begin
  if v_aid is null then return json_build_object('error','Kein Verband'); end if;
  return json_build_object('can_create',_ally_perm(v_uid,'courses'),'kasse',(select kasse from app_alliances where id=v_aid),
    'courses',coalesce((select json_agg(json_build_object('id',c.id,'building',c.building_id,'academy',b.name,'course',c.course,'by',u.username,
      'per_member',c.per_member,'fee',c.fee,'capacity',c.capacity,'starts_at',c.starts_at,'ends_at',c.ends_at,
      'seats',(select coalesce(sum(persons),0) from app_ally_course_seats s where s.course_id=c.id),
      'mine',(select coalesce(sum(persons),0) from app_ally_course_seats s where s.course_id=c.id and s.user_id=v_uid),
      'members',(select coalesce(json_agg(json_build_object('name',su.username,'persons',s.persons) order by s.at),'[]'::json) from app_ally_course_seats s join app_users su on su.id=s.user_id where s.course_id=c.id))
      order by c.starts_at) from app_ally_courses c join app_alliance_buildings b on b.id=c.building_id left join app_users u on u.id=c.created_by
      where c.alliance_id=v_aid and c.ends_at > now()),'[]'::json));
end; $$;
-- Ausschreiben: Kasse zahlt 150.000 €, belegt einen Lehrsaal bis zum Ende; Start in 1/3/6/12/24 h; Dauer 3–7 Tage
create or replace function ally_course_create(p_token uuid, p_building uuid, p_course text, p_duration bigint, p_start_h int, p_per_member int, p_fee bigint)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); b app_alliance_buildings; v_start timestamptz; v_id uuid; v_kasse bigint;
begin
  if v_aid is null or not _ally_perm(v_uid,'courses') then return json_build_object('error','Keine Berechtigung (Lehrgangsleitung)'); end if;
  select * into b from app_alliance_buildings where id=p_building and alliance_id=v_aid and type='akademie';
  if b.id is null then return json_build_object('error','Verbandsakademie nicht gefunden'); end if;
  if coalesce(p_course,'') !~ '^[A-Za-z0-9_-]{1,40}$' then return json_build_object('error','Ungültiger Lehrgang'); end if;
  if p_start_h not in (1,3,6,12,24) then return json_build_object('error','Start in 1, 3, 6, 12 oder 24 Stunden'); end if;
  if coalesce(p_per_member,0) < 1 or p_per_member > 10 then return json_build_object('error','Plätze je Mitglied: 1 bis 10'); end if;
  if coalesce(p_fee,0) < 0 or p_fee > 100000 then return json_build_object('error','Gebühr je Person: 0 bis 100.000 €'); end if;
  perform pg_advisory_xact_lock(hashtext('a:'||b.id));
  if (select count(*) from app_ally_courses where building_id=b.id and ends_at > now()) >= b.rooms then return json_build_object('error','Alle Lehrsäle belegt'); end if;
  select kasse into v_kasse from app_alliances where id=v_aid for update;
  if v_kasse < 150000 then return json_build_object('error','Zu wenig in der Verbandskasse (150.000 € nötig)'); end if;
  update app_alliances set kasse=kasse-150000 where id=v_aid;
  v_start := now() + make_interval(hours=>p_start_h);
  insert into app_ally_courses(alliance_id, building_id, course, created_by, per_member, fee, starts_at, ends_at)
    values (v_aid, b.id, p_course, v_uid, p_per_member, p_fee, v_start, v_start + make_interval(secs=>greatest(259200000, least(604800000, coalesce(p_duration,604800000)))/1000.0))
    returning id into v_id;
  insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_aid, v_uid, 'lehrgang', -150000, 'Lehrgang '||p_course||' in '||b.name||' ausgeschrieben');
  insert into app_alliance_radio(alliance_id, user_id, vehicle, status, note) values (v_aid, v_uid, 'Verbandsakademie', null, 'Lehrgang ausgeschrieben: '||p_course||' in '||b.name);
  return json_build_object('ok',true,'id',v_id);
end; $$;
-- Anmelden bis zum Start; Gebühr je Person geht vom gespeicherten Guthaben in die Kasse
create or replace function ally_course_join(p_token uuid, p_course uuid, p_persons int)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); c app_ally_courses; v_mine int; v_all int; v_fee bigint;
begin
  if v_aid is null then return json_build_object('error','Kein Verband'); end if;
  select * into c from app_ally_courses where id=p_course and alliance_id=v_aid for update;
  if c.id is null then return json_build_object('error','Lehrgang nicht gefunden'); end if;
  if c.starts_at <= now() then return json_build_object('error','Anmeldung geschlossen – der Lehrgang läuft schon'); end if;
  if coalesce(p_persons,0) < 1 then return json_build_object('error','Mindestens eine Person'); end if;
  select coalesce(sum(persons),0) into v_all from app_ally_course_seats where course_id=c.id;
  select coalesce(sum(persons),0) into v_mine from app_ally_course_seats where course_id=c.id and user_id=v_uid;
  if v_mine + p_persons > c.per_member then return json_build_object('error','Höchstens '||c.per_member||' Personen je Mitglied (noch '||greatest(0,c.per_member-v_mine)||')'); end if;
  if v_all + p_persons > c.capacity then return json_build_object('error','Nur noch '||greatest(0,c.capacity-v_all)||' Plätze frei'); end if;
  v_fee := c.fee * p_persons;
  if v_fee > 0 then
    if not _take_credits(v_uid, v_fee) then return json_build_object('error','Nicht genug Guthaben ('||v_fee||' €)'); end if;
    update app_alliances set kasse=kasse+v_fee where id=v_aid;
    insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_aid, v_uid, 'lehrgang', v_fee, 'Anmeldung '||c.course||' ('||p_persons||' Pers.)');
  end if;
  insert into app_ally_course_seats(course_id, user_id, persons) values (c.id, v_uid, p_persons)
    on conflict (course_id, user_id) do update set persons=app_ally_course_seats.persons+excluded.persons;
  return json_build_object('ok',true,'starts_at',c.starts_at,'ends_at',c.ends_at,'fee',v_fee);
end; $$;
-- Absagen vor dem Start, nur ohne Anmeldungen: 150.000 € zurück in die Kasse
create or replace function ally_course_cancel(p_token uuid, p_course uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); c app_ally_courses;
begin
  if v_aid is null or not _ally_perm(v_uid,'courses') then return json_build_object('error','Keine Berechtigung (Lehrgangsleitung)'); end if;
  select * into c from app_ally_courses where id=p_course and alliance_id=v_aid for update;
  if c.id is null then return json_build_object('error','Lehrgang nicht gefunden'); end if;
  if c.starts_at <= now() then return json_build_object('error','Der Lehrgang läuft schon'); end if;
  if exists(select 1 from app_ally_course_seats where course_id=c.id) then return json_build_object('error','Es sind schon Mitglieder angemeldet'); end if;
  delete from app_ally_courses where id=c.id;
  update app_alliances set kasse=kasse+150000 where id=v_aid;
  insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_aid, v_uid, 'lehrgang', 150000, 'Lehrgang '||c.course||' abgesagt');
  return json_build_object('ok',true);
end; $$;
-- Fachabteilung im Verbandskrankenhaus bauen (Recht Finanzen): 500.000 € bzw. 2 Mio. € (Herzkatheter, Stroke Unit, Brandverletzte),
-- Bauzeit 1 Tag, Abteilungen eines Hauses nacheinander (Bauschlange)
create or replace function ally_kh_dept(p_token uuid, p_id uuid, p_dept text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_aid uuid := _ally_of(v_uid); b app_alliance_buildings; v_cost bigint; v_kasse bigint; v_start timestamptz;
begin
  if v_aid is null or not _ally_perm(v_uid,'finance') then return json_build_object('error','Keine Berechtigung'); end if;
  select * into b from app_alliance_buildings where id=p_id and alliance_id=v_aid and type='kh' for update;
  if b.id is null then return json_build_object('error','Verbandskrankenhaus nicht gefunden'); end if;
  if b.depts is null then return json_build_object('error','Dieses Krankenhaus hat bereits alle Fachabteilungen'); end if;
  v_cost := case when p_dept in ('kar','str','bra') then 2000000 when p_dept in ('unf','geb','kin','psy') then 500000 end;
  if v_cost is null then return json_build_object('error','Unbekannte Fachabteilung'); end if;
  if exists(select 1 from jsonb_array_elements(b.depts) d where d->>'dept'=p_dept) then return json_build_object('error','Abteilung schon vorhanden oder im Bau'); end if;
  select kasse into v_kasse from app_alliances where id=v_aid for update;
  if v_kasse < v_cost then return json_build_object('error','Zu wenig in der Verbandskasse ('||v_cost||' € nötig)'); end if;
  select greatest(now(), coalesce(max((d->>'ready_at')::timestamptz), now())) into v_start from jsonb_array_elements(b.depts) d;
  update app_alliances set kasse=kasse-v_cost where id=v_aid;
  update app_alliance_buildings set depts=depts || jsonb_build_array(jsonb_build_object('dept',p_dept,'ready_at',coalesce(v_start,now())+interval '1 day')) where id=b.id;
  insert into app_alliance_ledger(alliance_id, user_id, kind, amount, note) values (v_aid, v_uid, 'gebaeude', -v_cost, 'Fachabteilung '||p_dept||' für '||b.name);
  return json_build_object('ok',true,'ready_at',coalesce(v_start,now())+interval '1 day');
end; $$;

/* ---------- Shop & Premium ----------
   Einsatzpunkte (EP) und Forschungspunkte (RP) liegen nur auf dem Server (app_wallet). EP kommen später per Stripe
   (Gutschrift über admin_ep_grant bzw. eine Edge Function mit Service-Role-Key, nie aus dem Browser).
   Premium kostet 50 EP je 30 Tage und verlängert sich automatisch, solange genug EP da sind. */
create table if not exists app_wallet (
  user_id uuid primary key references app_users(id) on delete cascade, ep int not null default 0, rp int not null default 0,
  premium_until timestamptz, premium_auto boolean not null default true, discord_id text, updated_at timestamptz not null default now() );
create table if not exists app_ep_ledger ( id bigserial primary key, user_id uuid not null references app_users(id) on delete cascade,
  amount int not null, kind text not null, note text not null default '', at timestamptz not null default now() );
create table if not exists app_research_nodes ( id text primary key, max_level int not null, premium_from int, rp int not null, minutes int not null, req text );
create table if not exists app_research ( user_id uuid not null references app_users(id) on delete cascade, node text not null,
  level int not null default 0, started_at timestamptz, done_at timestamptz, primary key (user_id, node) );
create table if not exists app_quests ( id text primary key, period text not null, premium boolean not null, money int not null, rp int not null );
alter table app_quests add column if not exists counter text not null default 'missions';
alter table app_quests add column if not exists goal int not null default 1;
-- Quest-Fortschritt je Spieler (zählt der Server beim Speichern aus dem Einnahmen-Protokoll)
create table if not exists app_quest_progress ( user_id uuid primary key references app_users(id) on delete cascade,
  day text, week text, d jsonb not null default '{}', w jsonb not null default '{}', last_t bigint );
create table if not exists app_quest_claims ( user_id uuid not null references app_users(id) on delete cascade, quest text not null, period_key text not null,
  at timestamptz not null default now(), primary key (user_id, quest, period_key) );
create table if not exists app_user_images ( user_id uuid not null references app_users(id) on delete cascade, slot text not null, data text not null,
  updated_at timestamptz not null default now(), primary key (user_id, slot) );
alter table app_codes add column if not exists premium_only boolean not null default false;
alter table app_wallet enable row level security; alter table app_ep_ledger enable row level security; alter table app_research_nodes enable row level security;
alter table app_research enable row level security; alter table app_quests enable row level security; alter table app_quest_claims enable row level security;
alter table app_user_images enable row level security;
alter table app_quest_progress enable row level security;
revoke all on app_wallet, app_ep_ledger, app_research_nodes, app_research, app_quests, app_quest_claims, app_user_images, app_quest_progress from anon, authenticated;

-- SHOPDATEN:BEGIN (automatisch erzeugt mit: node werkzeuge/preise_sql.cjs, nicht von Hand ändern)
delete from app_research_nodes;
insert into app_research_nodes(id, max_level, premium_from, rp, minutes, req) values
  ('lohn_fw',5,4,10,60,null),
  ('ausrueck',3,null,15,120,'lohn_fw'),
  ('fahrt',5,4,20,180,'ausrueck'),
  ('loesch',3,null,30,360,'fahrt'),
  ('lohn_rd',5,4,10,60,null),
  ('transport',3,null,15,120,'lohn_rd'),
  ('behandlung',3,null,20,180,'transport'),
  ('stabil',3,null,30,360,'behandlung'),
  ('erw_kosten',3,null,10,60,null),
  ('erw_bau',3,null,15,120,'erw_kosten'),
  ('personal_kosten',3,null,15,120,'erw_kosten'),
  ('zinsen',2,null,25,240,'erw_bau'),
  ('lehrgang_dauer',3,null,10,60,null),
  ('lehrgang_kosten',3,null,15,120,'lehrgang_dauer'),
  ('anwerben',2,null,20,180,'lehrgang_kosten'),
  ('manv',3,0,25,240,null),
  ('grosslage',3,0,35,480,'manv'),
  ('verlegung',2,0,30,360,'manv'),
  ('notruf',5,0,20,180,null),
  ('takt',3,0,30,360,'notruf'),
  ('telemedizin',2,0,30,360,'notruf');
delete from app_quests where id not in (select quest from app_quest_claims);
insert into app_quests(id, period, premium, money, rp, counter, goal) values
  ('d_einsaetze','d',false,50000,5,'missions',10),
  ('d_transporte','d',false,40000,5,'transports',5),
  ('d_rd','d',false,30000,3,'rd',3),
  ('d_einsaetze_p','d',true,150000,15,'missions',25),
  ('d_verlegung_p','d',true,100000,10,'iv',2),
  ('w_einsaetze','w',false,300000,30,'missions',75),
  ('w_transporte','w',false,250000,25,'transports',40),
  ('w_einsaetze_p','w',true,1000000,80,'missions',200),
  ('w_brand_p','w',true,600000,60,'fire_big',10)
on conflict (id) do update set period=excluded.period, premium=excluded.premium, money=excluded.money, rp=excluded.rp, counter=excluded.counter, goal=excluded.goal;
-- SHOPDATEN:END

-- Premium aktiv? Verlängert automatisch (50 EP), wenn abgelaufen und Auto-Verlängerung an
create or replace function _premium(p_uid uuid) returns boolean language plpgsql security definer set search_path=public, extensions as $$
declare w app_wallet;
begin
  insert into app_wallet(user_id) values (p_uid) on conflict do nothing;
  select * into w from app_wallet where user_id=p_uid for update;
  if w.premium_until is not null and w.premium_until > now() then return true; end if;
  if w.premium_until is not null and w.premium_auto and w.ep >= 50 then
    update app_wallet set ep=ep-50, premium_until=now()+interval '30 days', updated_at=now() where user_id=p_uid;
    insert into app_ep_ledger(user_id, amount, kind, note) values (p_uid, -50, 'premium', 'Premium automatisch verlängert');
    return true;
  end if;
  return false;
end; $$;
create or replace function _period_key(p text) returns text language sql stable as $$
  select case when p='d' then to_char(now() at time zone 'Europe/Berlin','YYYY-MM-DD') else to_char(now() at time zone 'Europe/Berlin','IYYY-"W"IW') end; $$;

/* Quest-Fortschritt: neue Protokolleinträge (t > last_t) zählen, aber nur wenn ihre Einnahmen durch den beim Speichern
   akzeptierten Zuwachs gedeckt sind (Zuwachs + Ausgaben ohne Fahrzeug-/Gebäudekäufe). Zähler: missions, rd, iv, fire_big, transports */
create or replace function _quest_track(p_uid uuid, p_data jsonb, p_gain numeric) returns void language plpgsql security definer set search_path=public, extensions as $$
declare qp app_quest_progress; v_now bigint := (extract(epoch from now())*1000)::bigint; e jsonb; v_t bigint; v_a numeric; v_c text; v_x text;
  v_inc numeric := 0; v_spend numeric := 0; v_max bigint; cnt jsonb := '{}'; k text; v_day text := _period_key('d'); v_week text := _period_key('w');
begin
  insert into app_quest_progress(user_id) values (p_uid) on conflict do nothing;
  select * into qp from app_quest_progress where user_id=p_uid for update;
  if qp.last_t is null then update app_quest_progress set last_t=v_now, day=v_day, week=v_week where user_id=p_uid; return; end if;   -- ab jetzt zählen
  for e in select value from jsonb_array_elements(_jarr(p_data,'ledger')) loop
    v_t := _jnum(e,'t')::bigint; if v_t <= qp.last_t or v_t > v_now + 60000 then continue; end if;
    v_a := _jnum(e,'a'); v_c := coalesce(e->>'c',''); v_x := coalesce(e->>'x','');
    v_max := greatest(coalesce(v_max,0), v_t);
    if v_a > 0 and v_c not in ('erstattung','korrektur') then
      v_inc := v_inc + v_a;
      if v_c in ('einsatz_fw','einsatz_rd') then cnt := jsonb_set(cnt,'{missions}',to_jsonb(coalesce((cnt->>'missions')::int,0)+1)); end if;
      if v_c='einsatz_rd' and v_x ~ '^IV' then cnt := jsonb_set(cnt,'{iv}',to_jsonb(coalesce((cnt->>'iv')::int,0)+1));
      elsif v_c='einsatz_rd' then cnt := jsonb_set(cnt,'{rd}',to_jsonb(coalesce((cnt->>'rd')::int,0)+1)); end if;
      if v_c='einsatz_fw' and v_x ~ '^BRAND [3-9]' then cnt := jsonb_set(cnt,'{fire_big}',to_jsonb(coalesce((cnt->>'fire_big')::int,0)+1)); end if;
      if v_c='transport' then cnt := jsonb_set(cnt,'{transports}',to_jsonb(coalesce((cnt->>'transports')::int,0)+1)); end if;
    elsif v_a < 0 and v_c not in ('fahrzeug','gebaeude','korrektur') then v_spend := v_spend - v_a;
    end if;
  end loop;
  if v_max is null then return; end if;
  if qp.day is distinct from v_day then qp.d := '{}'; end if;
  if qp.week is distinct from v_week then qp.w := '{}'; end if;
  if v_inc <= greatest(0,p_gain) + v_spend + 1000 then
    for k in select jsonb_object_keys(cnt) loop
      qp.d := jsonb_set(qp.d, array[k], to_jsonb(coalesce((qp.d->>k)::int,0) + (cnt->>k)::int));
      qp.w := jsonb_set(qp.w, array[k], to_jsonb(coalesce((qp.w->>k)::int,0) + (cnt->>k)::int));
    end loop;
  end if;
  update app_quest_progress set day=v_day, week=v_week, d=qp.d, w=qp.w, last_t=greatest(qp.last_t, v_max) where user_id=p_uid;
end; $$;

create or replace function wallet(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); v_prem boolean; w app_wallet;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  v_prem := _premium(v_uid);
  select * into w from app_wallet where user_id=v_uid;
  return json_build_object('ok',true,'user_id',v_uid,'ep',w.ep,'rp',w.rp,'premium',v_prem,'premium_until',w.premium_until,'premium_auto',w.premium_auto,'discord_id',w.discord_id,
    'day',_period_key('d'),'week',_period_key('w'),
    'research',coalesce((select json_agg(json_build_object('node',node,'level',level,'started_at',started_at,'done_at',done_at)) from app_research where user_id=v_uid),'[]'::json),
    'claimed',coalesce((select json_agg(quest) from app_quest_claims c join app_quests q on q.id=c.quest where c.user_id=v_uid and c.period_key=_period_key(q.period)),'[]'::json),
    'progress',json_build_object(
      'd',coalesce((select qp.d from app_quest_progress qp where qp.user_id=v_uid and qp.day=_period_key('d')),'{}'::jsonb),
      'w',coalesce((select qp.w from app_quest_progress qp where qp.user_id=v_uid and qp.week=_period_key('w')),'{}'::jsonb)),
    'images',coalesce((select json_agg(slot) from app_user_images where user_id=v_uid),'[]'::json));
end; $$;
create or replace function premium_activate(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); w app_wallet;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  insert into app_wallet(user_id) values (v_uid) on conflict do nothing;
  select * into w from app_wallet where user_id=v_uid for update;
  if w.ep < 50 then return json_build_object('error','Nicht genug Einsatzpunkte (50 EP nötig)'); end if;
  update app_wallet set ep=ep-50, premium_until=greatest(now(),coalesce(premium_until,now()))+interval '30 days', updated_at=now() where user_id=v_uid;
  insert into app_ep_ledger(user_id, amount, kind, note) values (v_uid, -50, 'premium', 'Premium 30 Tage');
  return json_build_object('ok',true);
end; $$;
create or replace function premium_auto(p_token uuid, p_on boolean)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token);
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  insert into app_wallet(user_id) values (v_uid) on conflict do nothing;
  update app_wallet set premium_auto=coalesce(p_on,true), updated_at=now() where user_id=v_uid;
  return json_build_object('ok',true);
end; $$;
-- Discord-User-ID (Snowflake) für die VIP-Rolle; der Bot kommt später
create or replace function wallet_discord(p_token uuid, p_id text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token);
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  p_id := nullif(btrim(coalesce(p_id,'')),'');
  if p_id is not null and p_id !~ '^[0-9]{17,20}$' then return json_build_object('error','Ungültige Discord-User-ID (17–20 Ziffern)'); end if;
  insert into app_wallet(user_id) values (v_uid) on conflict do nothing;
  update app_wallet set discord_id=p_id, updated_at=now() where user_id=v_uid;
  return json_build_object('ok',true);
end; $$;

-- Forschung starten: eine gleichzeitig, Kosten rp×Stufe, Dauer minutes×Stufe
create or replace function research_start(p_token uuid, p_node text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); n app_research_nodes; v_lvl int; v_cost int; v_prem boolean; v_done timestamptz;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  select * into n from app_research_nodes where id=p_node;
  if n.id is null then return json_build_object('error','Unbekannte Forschung'); end if;
  v_prem := _premium(v_uid);
  if exists(select 1 from app_research where user_id=v_uid and done_at > now()) then return json_build_object('error','Es läuft schon eine Forschung'); end if;
  select coalesce(level,0) into v_lvl from app_research where user_id=v_uid and node=p_node; v_lvl := coalesce(v_lvl,0);
  if v_lvl >= n.max_level then return json_build_object('error','Höchste Stufe erreicht'); end if;
  if n.premium_from is not null and v_lvl+1 >= greatest(1,n.premium_from) and not v_prem then return json_build_object('error','Diese Stufe braucht Premium'); end if;
  if n.req is not null and coalesce((select level from app_research where user_id=v_uid and node=n.req and (done_at is null or done_at <= now())),0) < 1 then
    return json_build_object('error','Voraussetzung fehlt'); end if;
  v_cost := n.rp*(v_lvl+1);
  insert into app_wallet(user_id) values (v_uid) on conflict do nothing;
  update app_wallet set rp=rp-v_cost, updated_at=now() where user_id=v_uid and rp >= v_cost;
  if not found then return json_build_object('error','Nicht genug Forschungspunkte ('||v_cost||' RP nötig)'); end if;
  v_done := now() + make_interval(mins=>n.minutes*(v_lvl+1));
  insert into app_research(user_id, node, level, started_at, done_at) values (v_uid, p_node, v_lvl+1, now(), v_done)
    on conflict (user_id,node) do update set level=excluded.level, started_at=excluded.started_at, done_at=excluded.done_at;
  return json_build_object('ok',true,'level',v_lvl+1,'done_at',v_done,'cost',v_cost);
end; $$;

-- Quest abholen: einmal je Tag/Woche (Berliner Zeit); Geld wird dem Anti-Cheat als erlaubter Zuwachs gutgeschrieben
create or replace function quest_claim(p_token uuid, p_quest text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token); q app_quests;
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  select * into q from app_quests where id=p_quest;
  if q.id is null then return json_build_object('error','Unbekannte Quest'); end if;
  if q.premium and not _premium(v_uid) then return json_build_object('error','Diese Quest braucht Premium'); end if;
  if coalesce((select (case when q.period='d' then (case when qp.day=_period_key('d') then qp.d end) else (case when qp.week=_period_key('w') then qp.w end) end) ->> q.counter
      from app_quest_progress qp where qp.user_id=v_uid)::int, 0) < q.goal then return json_build_object('error','Quest noch nicht erfüllt'); end if;
  insert into app_quest_claims(user_id, quest, period_key) values (v_uid, q.id, _period_key(q.period)) on conflict do nothing;
  if not found then return json_build_object('error','Schon abgeholt'); end if;
  insert into app_wallet(user_id) values (v_uid) on conflict do nothing;
  update app_wallet set rp=rp+q.rp, updated_at=now() where user_id=v_uid;
  update app_saves set econ_adjust=coalesce(econ_adjust,0)+q.money where user_id=v_uid;
  return json_build_object('ok',true,'money',q.money,'rp',q.rp);
end; $$;

-- Eigene Grafiken (Premium): Slots v:<fahrzeugtyp>:<l|r><0|1> (Richtung, Blaulicht) bzw. b:<gebäude>:<normal|bau|verband>
create or replace function img_save(p_token uuid, p_slot text, p_data text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid := _uid(p_token);
begin
  if v_uid is null then return json_build_object('error','Sitzung ungültig'); end if;
  if not _premium(v_uid) then return json_build_object('error','Eigene Grafiken brauchen Premium'); end if;
  if coalesce(p_slot,'') !~ '^(v:[a-z0-9_]{1,30}:[lr][01]|b:[a-z_]{1,20}:(normal|bau|verband))$' then return json_build_object('error','Ungültiger Platz'); end if;
  if coalesce(p_data,'') !~ '^data:image/(png|webp);base64,[A-Za-z0-9+/=]+$' then return json_build_object('error','Nur PNG oder WebP'); end if;
  if length(p_data) > 280000 then return json_build_object('error','Bild zu groß (max. 200 KB)'); end if;
  if (select count(*) from app_user_images where user_id=v_uid and slot<>p_slot) >= 80 then return json_build_object('error','Höchstens 80 Grafiken'); end if;
  insert into app_user_images(user_id, slot, data) values (v_uid, p_slot, p_data)
    on conflict (user_id,slot) do update set data=excluded.data, updated_at=now();
  return json_build_object('ok',true);
end; $$;
create or replace function img_list(p_token uuid)
returns json language sql security definer set search_path=public, extensions as $$
  select coalesce(json_object_agg(slot, data),'{}'::json) from app_user_images where user_id=_uid(p_token); $$;
create or replace function img_delete(p_token uuid, p_slot text)
returns json language plpgsql security definer set search_path=public, extensions as $$
begin
  delete from app_user_images where user_id=_uid(p_token) and slot=p_slot;
  return json_build_object('ok',true);
end; $$;

-- Admin: EP gutschreiben (bis Stripe angebunden ist) und Premium-Spieler mit Discord-ID für die VIP-Rolle
create or replace function admin_ep_grant(p_token uuid, p_username text, p_amount int, p_note text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid;
begin
  if not _admin_ok(p_token) then return json_build_object('error','Nicht angemeldet'); end if;
  select id into v_uid from app_users where lower(username)=lower(btrim(coalesce(p_username,'')));
  if v_uid is null then return json_build_object('error','Spieler nicht gefunden'); end if;
  if coalesce(p_amount,0)=0 or abs(p_amount) > 100000 then return json_build_object('error','Betrag: ±1 bis 100.000 EP'); end if;
  insert into app_wallet(user_id) values (v_uid) on conflict do nothing;
  update app_wallet set ep=greatest(0,ep+p_amount), updated_at=now() where user_id=v_uid;
  insert into app_ep_ledger(user_id, amount, kind, note) values (v_uid, p_amount, 'admin', left(coalesce(p_note,''),200));
  return json_build_object('ok',true,'ep',(select ep from app_wallet where user_id=v_uid));
end; $$;
-- Admin: EP, Forschungspunkte (RP) oder Premium-Tage schenken bzw. abziehen (negativer Betrag)
create or replace function admin_grant(p_token uuid, p_username text, p_kind text, p_amount int, p_note text)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid; v_note text := left(btrim(coalesce(p_note,'')),200); v_max int := case p_kind when 'premium' then 3650 else 100000 end; w app_wallet;
begin
  if not _admin_ok(p_token) then return json_build_object('error','Nicht angemeldet'); end if;
  select id into v_uid from app_users where lower(username)=lower(btrim(coalesce(p_username,'')));
  if v_uid is null then return json_build_object('error','Spieler nicht gefunden'); end if;
  if p_kind not in ('ep','rp','premium') then return json_build_object('error','Unbekannte Art'); end if;
  if coalesce(p_amount,0)=0 or abs(p_amount) > v_max then
    return json_build_object('error', case p_kind when 'premium' then 'Tage: ±1 bis 3650' else 'Betrag: ±1 bis 100.000' end); end if;
  insert into app_wallet(user_id) values (v_uid) on conflict do nothing;
  if p_kind='ep' then
    update app_wallet set ep=greatest(0,ep+p_amount), updated_at=now() where user_id=v_uid;
    insert into app_ep_ledger(user_id, amount, kind, note) values (v_uid, p_amount, 'admin', v_note);
  elsif p_kind='rp' then
    update app_wallet set rp=greatest(0,rp+p_amount), updated_at=now() where user_id=v_uid;
  elsif p_amount > 0 then
    update app_wallet set premium_until=greatest(now(),coalesce(premium_until,now()))+make_interval(days=>p_amount), updated_at=now() where user_id=v_uid;
    insert into app_ep_ledger(user_id, amount, kind, note) values (v_uid, 0, 'admin', left('Premium +'||p_amount||' Tage geschenkt'||case when v_note<>'' then ' · '||v_note else '' end,200));
  else
    -- Abziehen: endet höchstens jetzt (keine automatische Verlängerung ausgelöst, solange premium_until in der Vergangenheit bleibt)
    update app_wallet set premium_until=case when premium_until is null or premium_until <= now() then premium_until
      else greatest(now(), premium_until+make_interval(days=>p_amount)) end, updated_at=now() where user_id=v_uid;
  end if;
  select * into w from app_wallet where user_id=v_uid;
  return json_build_object('ok',true,'ep',w.ep,'rp',w.rp,'premium_until',w.premium_until);
end; $$;
create or replace function admin_premium_list(p_token uuid)
returns json language plpgsql security definer set search_path=public, extensions as $$
begin
  if not _admin_ok(p_token) then return json_build_object('error','Nicht angemeldet'); end if;
  return json_build_object('ok',true,'list',coalesce((select json_agg(json_build_object('name',u.username,'ep',w.ep,'rp',w.rp,'premium_until',w.premium_until,'auto',w.premium_auto,'discord_id',w.discord_id)
    order by w.premium_until desc nulls last) from app_wallet w join app_users u on u.id=w.user_id where w.premium_until is not null or w.ep > 0 or w.rp > 0 or w.discord_id is not null),'[]'::json));
end; $$;

/* ---------- Stripe: EP-Käufe ----------
   Die Edge Function supabase/functions/stripe-webhook prüft die Stripe-Signatur und ruft ep_credit_purchase mit dem
   Service-Role-Key auf. Jede Checkout-Session wird nur einmal gutgeschrieben. Aus dem Browser (anon) nicht aufrufbar. */
create table if not exists app_payments ( session_id text primary key, user_id uuid references app_users(id) on delete set null,
  ep int not null, cents int not null, at timestamptz not null default now() );
alter table app_payments enable row level security;
revoke all on app_payments from anon, authenticated;
create or replace function ep_credit_purchase(p_session text, p_user uuid, p_ep int, p_cents int)
returns json language plpgsql security definer set search_path=public, extensions as $$
begin
  if coalesce(p_session,'') = '' or coalesce(p_ep,0) <= 0 or p_ep > 100000 then return json_build_object('error','Ungültiger Kauf'); end if;
  if not exists(select 1 from app_users where id=p_user) then return json_build_object('error','Spieler nicht gefunden'); end if;
  insert into app_payments(session_id, user_id, ep, cents) values (p_session, p_user, p_ep, coalesce(p_cents,0)) on conflict do nothing;
  if not found then return json_build_object('ok',true,'duplicate',true); end if;
  insert into app_wallet(user_id) values (p_user) on conflict do nothing;
  update app_wallet set ep=ep+p_ep, updated_at=now() where user_id=p_user;
  insert into app_ep_ledger(user_id, amount, kind, note) values (p_user, p_ep, 'kauf', 'Stripe '||left(p_session,80)||' · '||round(coalesce(p_cents,0)/100.0,2)||' €');
  return json_build_object('ok',true,'ep',(select ep from app_wallet where user_id=p_user));
end; $$;

grant execute on all functions in schema public to anon, authenticated;
-- Interne Hilfsfunktionen nicht von außen aufrufbar
revoke execute on function _uid(uuid), _maint(), _new_session(uuid), _token_hash(uuid), _client_ip(), _login_locked(text[]), _login_fail(text[]),
  _jnum(jsonb,text), _jlevel(jsonb,int), _jarr(jsonb,text), _assets(jsonb), _vehicle_count(jsonb),
  _ally_of(uuid), _ally_is_owner(uuid), _ally_perm(uuid,text), _ally_rank(uuid), _take_credits(uuid,bigint), _ally_join(uuid,uuid), _ally_remove(uuid),
  _ally_banned(uuid,uuid), _sm_tick(uuid), _ally_muted(uuid,uuid), _ally_academies(uuid),
  _admin_ok(uuid), _code_rewards(jsonb), admin_set_password(text), _premium(uuid), _period_key(text), _quest_track(uuid,jsonb,numeric),
  ep_credit_purchase(text,uuid,int,int) from public, anon, authenticated;
grant execute on function ep_credit_purchase(text,uuid,int,int) to service_role;   -- nur die Edge Function (Service-Role-Key)

notify pgrst, 'reload schema';
