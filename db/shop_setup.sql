-- ============================================================================
--  LEITSTELLE — Shop (Stripe, Ingame-Geld-Pakete)
--  Im Supabase SQL Editor ausführen (nach dem Haupt-Setup). Mehrfach ok.
-- ============================================================================
set search_path = public, extensions;

-- Angebote (öffentlich lesbar, damit der Client sie anzeigen kann)
create table if not exists shop_products (
  id text primary key,
  name text not null,
  price_cents int not null,            -- Preis in Cent (199 = 1,99 €)
  currency text not null default 'eur',
  credits bigint not null,             -- Ingame-Geld, das gutgeschrieben wird
  active boolean not null default true,
  sort int not null default 0
);
alter table shop_products enable row level security;
drop policy if exists shop_products_read on shop_products;
create policy shop_products_read on shop_products for select using (active);
grant select on shop_products to anon, authenticated;

-- Kauf-Protokoll (kein Client-Zugriff; nur Edge Function via service_role)
create table if not exists shop_purchases (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references app_users(id) on delete set null,
  product_id text,
  stripe_session_id text unique,
  amount_cents int,
  credits bigint,
  status text default 'completed',
  created_at timestamptz not null default now()
);
alter table shop_purchases enable row level security;   -- keine Policy = kein Client-Zugriff

-- Sichere Gutschrift (idempotent). Nur vom Webhook (service_role) aufrufbar.
create or replace function shop_grant(p_user_id uuid, p_credits bigint, p_product text, p_session text, p_amount int)
returns json language plpgsql security definer set search_path=public, extensions as $$
declare v_new bigint;
begin
  if p_user_id is null then return json_build_object('error','kein user'); end if;
  if exists(select 1 from shop_purchases where stripe_session_id=p_session) then
    return json_build_object('ok',true,'dup',true);       -- schon verbucht
  end if;
  insert into app_saves(user_id,data) values (p_user_id,'{}'::jsonb) on conflict (user_id) do nothing;
  update app_saves set data = jsonb_set(coalesce(data,'{}'::jsonb),'{credits}',
      to_jsonb( coalesce((case when (data->>'credits') ~ '^-?[0-9]+(\.[0-9]+)?$'
                               then floor((data->>'credits')::numeric)::bigint else 0 end),0) + p_credits ), true),
      updated_at=now()
    where user_id=p_user_id returning (data->>'credits')::bigint into v_new;
  insert into shop_purchases(user_id,product_id,stripe_session_id,amount_cents,credits)
    values (p_user_id,p_product,p_session,p_amount,p_credits);
  return json_build_object('ok',true,'credits',v_new);
end; $$;
revoke execute on function shop_grant(uuid,bigint,text,text,int) from public, anon, authenticated;
grant  execute on function shop_grant(uuid,bigint,text,text,int) to service_role;

-- Token → user_id (nur service_role; für die Checkout-Funktion)
create or replace function shop_uid(p_token uuid)
returns uuid language sql security definer set search_path=public, extensions as $$
  select user_id from app_sessions where token=p_token;
$$;
revoke execute on function shop_uid(uuid) from public, anon, authenticated;
grant  execute on function shop_uid(uuid) to service_role;

-- Beispiel-Pakete (Preise/Beträge frei anpassbar)
insert into shop_products(id,name,price_cents,credits,sort) values
  ('p1','1.000.000 € Bargeld',   199,  1000000, 1),
  ('p2','5.000.000 € Bargeld',   499,  5000000, 2),
  ('p3','15.000.000 € Bargeld',  999, 15000000, 3),
  ('p4','50.000.000 € Bargeld', 1999, 50000000, 4)
on conflict (id) do update set name=excluded.name, price_cents=excluded.price_cents, credits=excluded.credits, sort=excluded.sort, active=true;

notify pgrst, 'reload schema';
