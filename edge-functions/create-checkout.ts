// Supabase Edge Function:  create-checkout
// Erstellt eine Stripe-Checkout-Session — OHNE Stripe-SDK (reines fetch),
// damit es im Supabase-Edge-Runtime (Deno 2.x) läuft.
// Dashboard: "Verify JWT" AN lassen.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const STRIPE_SECRET = Deno.env.get("STRIPE_SECRET_KEY")!;
const admin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    if (!STRIPE_SECRET) { console.error("STRIPE_SECRET_KEY fehlt"); return json({ error: "STRIPE_SECRET_KEY nicht gesetzt" }, 500); }
    const { token, productId, successUrl, cancelUrl } = await req.json();
    console.log("checkout request", { productId, hasToken: !!token });
    if (!token || !productId) return json({ error: "token/productId fehlt" }, 400);

    const { data: uid, error: uErr } = await admin.rpc("shop_uid", { p_token: token });
    if (uErr) { console.error("shop_uid err", uErr); return json({ error: "shop_uid: " + uErr.message }, 500); }
    if (!uid) { console.error("kein user fuer token"); return json({ error: "Sitzung ungültig (bitte neu einloggen)" }, 401); }

    const { data: prod, error: pErr } = await admin
      .from("shop_products").select("*").eq("id", productId).eq("active", true).maybeSingle();
    if (pErr) { console.error("shop_products err", pErr); return json({ error: "shop_products: " + pErr.message }, 500); }
    if (!prod) { console.error("produkt fehlt", productId); return json({ error: "Produkt nicht gefunden" }, 404); }

    const base = successUrl || "https://example.com/";
    const cbase = cancelUrl || base;
    const p = new URLSearchParams();
    p.set("mode", "payment");
    p.set("success_url", base + "?purchase=success");
    p.set("cancel_url", cbase + "?purchase=cancel");
    p.set("line_items[0][quantity]", "1");
    p.set("line_items[0][price_data][currency]", prod.currency || "eur");
    p.set("line_items[0][price_data][unit_amount]", String(prod.price_cents));
    p.set("line_items[0][price_data][product_data][name]", prod.name);
    p.set("metadata[user_id]", String(uid));
    p.set("metadata[product_id]", prod.id);
    p.set("metadata[credits]", String(prod.credits));
    p.set("managed_payments[enabled]", "false");   // sonst verlangt Stripe einen Steuer-Code je Artikel

    const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${STRIPE_SECRET}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: p.toString(),
    });
    const session = await res.json();
    if (!res.ok) { console.error("stripe error", session?.error); return json({ error: session?.error?.message || "Stripe-Fehler" }, 400); }
    console.log("checkout ok", session.id);
    return json({ url: session.url });
  } catch (e) {
    console.error("checkout exception", e);
    return json({ error: String((e as Error)?.message || e) }, 500);
  }
});
