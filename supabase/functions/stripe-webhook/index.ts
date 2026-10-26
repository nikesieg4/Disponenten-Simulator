// Stripe-Webhook: schreibt nach einer erfolgreichen Zahlung die Einsatzpunkte (EP) gut.
// Geheimnisse liegen nur als Supabase-Secrets vor (nie im Repository):
//   supabase secrets set STRIPE_SECRET_KEY=sk_... STRIPE_WEBHOOK_SECRET=whsec_...
//   supabase functions deploy stripe-webhook --no-verify-jwt
// SUPABASE_URL und SUPABASE_SERVICE_ROLE_KEY stellt Supabase der Funktion automatisch bereit.
// Stripe-Ereignisse: checkout.session.completed und checkout.session.async_payment_succeeded
import Stripe from 'npm:stripe@17.7.0';
import { createClient } from 'npm:@supabase/supabase-js@2.49.1';

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY') ?? '');
const crypto = Stripe.createSubtleCryptoProvider();
const db = createClient(Deno.env.get('SUPABASE_URL') ?? '', Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '', { auth: { persistSession: false } });

// Preis in Cent -> EP (muss zu EP_PACKAGES in index.html passen)
const EP_BY_CENTS: Record<number, number> = { 999: 110, 1999: 220, 2999: 340, 4999: 575, 8499: 1100 };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

Deno.serve(async (req) => {
  if (req.method !== 'POST') return new Response('Method not allowed', { status: 405 });
  const signature = req.headers.get('stripe-signature');
  const body = await req.text();
  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(body, signature ?? '', Deno.env.get('STRIPE_WEBHOOK_SECRET') ?? '', undefined, crypto);
  } catch (e) {
    console.error('Signatur ungültig', e instanceof Error ? e.message : e);
    return new Response('Invalid signature', { status: 400 });
  }

  if (event.type === 'checkout.session.completed' || event.type === 'checkout.session.async_payment_succeeded') {
    const s = event.data.object as Stripe.Checkout.Session;
    if (s.payment_status !== 'paid') return new Response('Zahlung noch offen', { status: 200 });   // z. B. SEPA: kommt später als async_payment_succeeded
    const cents = s.amount_total ?? 0, ep = s.currency === 'eur' ? EP_BY_CENTS[cents] : undefined, user = s.client_reference_id ?? '';
    if (!ep || !UUID.test(user)) {
      console.error('Kauf nicht zuordenbar – bitte von Hand prüfen', { session: s.id, cents, currency: s.currency, user });
      return new Response('Nicht zuordenbar', { status: 200 });
    }
    const { data, error } = await db.rpc('ep_credit_purchase', { p_session: s.id, p_user: user, p_ep: ep, p_cents: cents });
    if (error) { console.error('Gutschrift fehlgeschlagen', error); return new Response('Fehler', { status: 500 }); }   // Stripe versucht es erneut
    if (data?.error) console.error('Gutschrift abgelehnt', { session: s.id, user, reason: data.error });
  }
  return new Response('ok', { status: 200 });
});
