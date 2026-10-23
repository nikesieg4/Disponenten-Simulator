-- ============================================================================
--  Nachtrag: Admin darf fremde Spielstände laden/schreiben (für Personal/Fahrzeug).
--  Im Supabase SQL Editor ausführen. Mehrfach ok.
-- ============================================================================
set search_path = public, extensions;

create or replace function app_admin_load_save(p_token uuid, p_username text)
returns jsonb language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid; v_data jsonb;
begin
  if not _is_admin(p_token) then return json_build_object('error','Kein Adminzugriff')::jsonb; end if;
  select id into v_uid from app_users where lower(username)=lower(p_username);
  if v_uid is null then return json_build_object('error','Benutzer nicht gefunden')::jsonb; end if;
  select data into v_data from app_saves where user_id=v_uid;
  return coalesce(v_data, '{}'::jsonb);
end; $$;

create or replace function app_admin_write_save(p_token uuid, p_username text, p_data jsonb)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_uid uuid;
begin
  if not _is_admin(p_token) then return json_build_object('error','Kein Adminzugriff'); end if;
  select id into v_uid from app_users where lower(username)=lower(p_username);
  if v_uid is null then return json_build_object('error','Benutzer nicht gefunden'); end if;
  insert into app_saves(user_id, data) values (v_uid, p_data)
    on conflict (user_id) do update set data=excluded.data, updated_at=now();
  return json_build_object('ok', true);
end; $$;

grant execute on function app_admin_load_save(uuid,text)        to anon, authenticated;
grant execute on function app_admin_write_save(uuid,text,jsonb) to anon, authenticated;
notify pgrst, 'reload schema';
