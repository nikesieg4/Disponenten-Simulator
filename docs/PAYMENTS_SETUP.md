# Zahlungen einrichten (Stripe + Supabase Edge Functions)

Alles läuft über das **Supabase-Dashboard** und das **Stripe-Dashboard** — keine CLI nötig.
Baue/teste zuerst komplett im **Stripe-Test-Modus** (kostenlos, mit Testkarten).

---

## 1) Stripe-Konto & Schlüssel
1. Konto anlegen auf https://dashboard.stripe.com (oben links „Testmodus" aktiviert lassen).
2. Developers → **API keys**: kopiere den **Secret key** (`sk_test_…`). Den brauchst du gleich.
   (Der „Publishable key" wird hier nicht benötigt — Checkout läuft serverseitig.)

## 2) Datenbank
Im Supabase → **SQL Editor** die Datei **`shop_setup.sql`** einfügen und **RUN**.
Das legt die Tabellen `shop_products`, `shop_purchases`, die sichere Gutschrift-Funktion
und vier Beispiel-Pakete an. (Preise/Beträge kannst du in der Tabelle `shop_products`
jederzeit ändern.)

## 3) Edge Functions anlegen (Dashboard)
Supabase → **Edge Functions** → **Create a new function**.

**Function 1 — Name genau: `create-checkout`**
- Code aus **`edge-create-checkout.ts`** einfügen.
- „Verify JWT" **AN** lassen.
- **Deploy**.

**Function 2 — Name genau: `stripe-webhook`**
- Code aus **`edge-stripe-webhook.ts`** einfügen.
- „Verify JWT" **AUS**schalten (Stripe schickt keinen Supabase-Token). Falls das Dashboard
  den Schalter nicht zeigt: unter Function → Settings „Enforce JWT verification" deaktivieren.
- **Deploy**.

## 4) Geheimnisse (Secrets) setzen
Supabase → **Edge Functions** → **Secrets** (oder Project Settings → Edge Functions → Secrets).
Füge hinzu:
- `STRIPE_SECRET_KEY`   = dein `sk_test_…`
- `STRIPE_WEBHOOK_SECRET` = kommt in Schritt 5 (erstmal Platzhalter, später eintragen)

(`SUPABASE_URL` und `SUPABASE_SERVICE_ROLE_KEY` sind automatisch vorhanden — nichts tun.)

## 5) Stripe-Webhook einrichten
1. Stripe → Developers → **Webhooks** → **Add endpoint**.
2. Endpoint-URL:
   `https://virsphrwhskjquenyhsj.supabase.co/functions/v1/stripe-webhook`
3. Events: **`checkout.session.completed`** auswählen.
4. Endpoint speichern → dir wird ein **Signing secret** (`whsec_…`) angezeigt.
5. Dieses `whsec_…` in Supabase als Secret **`STRIPE_WEBHOOK_SECRET`** eintragen
   (Schritt 4) und die Function `stripe-webhook` einmal neu **deployen**, damit sie das Secret lädt.

## 6) index.html hochladen
Die aktuelle `index.html` auf Netlify hochladen. Der Shop lädt die Angebote automatisch
aus `shop_products`. Beim Kauf leitet er zu Stripe und danach zurück ins Spiel
(Guthaben wird per Webhook gutgeschrieben).

## 7) Testen (Test-Modus)
- Im Spiel Menü ☰ → **Shop** → Paket wählen → „Bezahlen".
- Stripe-Testkarte: **4242 4242 4242 4242**, beliebiges künftiges Datum, beliebiger CVC/PLZ.
- Zurück im Spiel erscheint „Zahlung erfolgreich" und nach ein paar Sekunden das neue Guthaben.
- Kontrolle: In Supabase → Table Editor → `shop_purchases` steht der Kauf.

---

## Live gehen (später, wichtig)
- In Stripe von **Test** auf **Live** umstellen: Live-`sk_live_…` als `STRIPE_SECRET_KEY`
  setzen und einen **Live-Webhook** mit neuem `whsec_…` anlegen (gleiche URL, Live-Modus).
- Für echte Zahlungen verlangt Stripe eine **verifizierte Person/Firma mit Steuerdaten**.
- Rechtlich brauchst du dann u. a. **Impressum, AGB/Widerruf, Datenschutz** und musst
  **Umsatzsteuer** korrekt behandeln. Das ist dein Verantwortungsbereich — kläre das,
  bevor du echtes Geld annimmst.

## Fehlersuche
- Shop zeigt „nicht verfügbar" → `shop_setup.sql` nicht ausgeführt.
- Kauf-Button Fehler → `create-checkout` nicht deployt, `STRIPE_SECRET_KEY` fehlt,
  oder „Verify JWT" falsch. Logs: Supabase → Edge Functions → Function → Logs.
- Bezahlt, aber kein Guthaben → Webhook-URL/Event falsch, `STRIPE_WEBHOOK_SECRET`
  nicht gesetzt, oder „Verify JWT" beim Webhook nicht ausgeschaltet. Stripe → Webhooks →
  Endpoint zeigt fehlgeschlagene Zustellungen mit Fehlermeldung.
