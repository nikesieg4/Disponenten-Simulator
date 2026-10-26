# stripe-webhook

Schreibt nach einer Stripe-Zahlung die Einsatzpunkte gut (über `ep_credit_purchase` in `db/supabase_setup.sql`).

1. Supabase-CLI installieren und anmelden: `npx supabase login`, dann im Repo `npx supabase link --project-ref virsphrwhskjquenyhsj`
2. Geheimnisse setzen (nie ins Repository):
   `npx supabase secrets set STRIPE_SECRET_KEY=sk_test_... STRIPE_WEBHOOK_SECRET=whsec_...`
3. Hochladen: `npx supabase functions deploy stripe-webhook --no-verify-jwt`
   (`--no-verify-jwt`, weil Stripe kein Supabase-Token mitschickt; die Funktion prüft stattdessen die Stripe-Signatur.)
4. In Stripe unter Entwickler → Webhooks den Endpunkt
   `https://virsphrwhskjquenyhsj.supabase.co/functions/v1/stripe-webhook` anlegen, Ereignisse
   `checkout.session.completed` und `checkout.session.async_payment_succeeded`.

Die Preise in `EP_BY_CENTS` müssen zu `EP_PACKAGES` in `index.html` passen. Nicht zuordenbare Käufe stehen im Log der Funktion
(Supabase → Edge Functions → stripe-webhook → Logs) und lassen sich in der Admin-Seite von Hand gutschreiben.
Beim Wechsel in den Live-Modus: neue Payment Links in `EP_PACKAGES`, neue Secrets (`sk_live_…`, neues `whsec_…`), Webhook im Live-Modus anlegen.
