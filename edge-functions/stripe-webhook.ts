// Supabase Edge Function:  stripe-webhook
// Verbucht Ingame-Geld NACH bestätigter Zahlung — OHNE Stripe-SDK.
// Signaturprüfung selbst mit Web-Crypto (HMAC-SHA256).
// Dashboard: "Verify JWT" AUS.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const WH_SECRET = Deno.env.get("STRIPE_WEBHOOK_SECRET")!;
const admin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

async function verifyStripeSig(rawBody: string, sigHeader: string, secret: string): Promise<boolean> {
  try {
    const parts: Record<string, string> = {};
    for (const kv of sigHeader.split(",")) {
      const i = kv.indexOf("="); if (i > 0) parts[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
    }
    const t = parts["t"]; const v1 = parts["v1"];
    if (!t || !v1) return false;
    // optional: Zeitfenster 5 min
    if (Math.abs(Date.now() / 1000 - Number(t)) > 300) return false;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const mac = await crypto.subtle.sign("HMAC", key, enc.encode(`${t}.${rawBody}`));
    const hex = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
    // konstanter Vergleich
    if (hex.length !== v1.length) return false;
    let diff = 0; for (let i = 0; i < hex.length; i++) diff |= hex.charCodeAt(i) ^ v1.charCodeAt(i);
    return diff === 0;
  } catch { return false; }
}

Deno.serve(async (req) => {
  const sig = req.headers.get("stripe-signature") || "";
  const body = await req.text();
  if (!WH_SECRET) return new Response("STRIPE_WEBHOOK_SECRET nicht gesetzt", { status: 500 });
  if (!(await verifyStripeSig(body, sig, WH_SECRET))) return new Response("Signatur ungültig", { status: 400 });

  let event: any;
  try { event = JSON.parse(body); } catch { return new Response("bad json", { status: 400 }); }

  if (event.type === "checkout.session.completed") {
    const s = event.data?.object || {};
    const m = s.metadata || {};
    const { error } = await admin.rpc("shop_grant", {
      p_user_id: m.user_id,
      p_credits: Number(m.credits || 0),
      p_product: m.product_id || null,
      p_session: s.id,
      p_amount: s.amount_total || null,
    });
    if (error) { console.error("grant error", error); return new Response("grant error", { status: 500 }); }
  }
  return new Response("ok", { status: 200 });
});
