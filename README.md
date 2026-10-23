# Disponenten-Simulator (Leitstelle)

Ein browserbasiertes Leitstellen-/Feuerwehr-Dispositionsspiel als **einzelne `index.html`** —
Karte (Leaflet/OpenStreetMap), echte Straßen-Routen (OSRM), FMS-Funkstatus, Wachen,
Fahrzeuge, Personal, Lehrgänge und Einsätze.

Backend: **Supabase** (Login, Spielstände, Admin) und optional **Stripe** (Shop) über
Supabase Edge Functions. In der `index.html` stehen nur die öffentliche Supabase-URL und
der Anon-Key (durch RLS geschützt) — **keine** geheimen Schlüssel.

## Hosting (GitHub Pages)

Die `index.html` liegt im Hauptverzeichnis. Unter **Settings → Pages** als Quelle
„Deploy from a branch", Branch `main`, Ordner `/ (root)` wählen. Danach ist das Spiel
unter `https://<user>.github.io/disponenten-simulator/` erreichbar.

Die Seite ist in sich geschlossen (alle Bibliotheken per HTTPS-CDN) und läuft von jeder
Domain — ein Wechsel des Hosters erfordert keine Code-Änderung.

## Einrichtung des Backends

1. Supabase-Projekt anlegen.
2. SQL im Supabase SQL-Editor ausführen (in dieser Reihenfolge):
   - `db/supabase_setup.sql` — Tabellen, Auth, Admin, Bann/Wartung/Flagging
   - `db/shop_setup.sql` — Shop-Produkte (nur falls der Shop genutzt wird)
   - `db/admin_accounts.sql` — Admin: fremde Spielstände laden/schreiben
3. In `index.html` oben `SUPABASE_URL` und `SUPABASE_ANON_KEY` eintragen (bereits gesetzt).
4. Admin-Login: `Administrator / 2521` (für Live-Betrieb ändern!).

## Zahlungen (optional)

Siehe `docs/PAYMENTS_SETUP.md`. Die Edge Functions liegen in `edge-functions/` und werden
im Supabase-Dashboard als Funktionen `create-checkout` und `stripe-webhook` deployt.
Der Stripe-Secret-Key und der Service-Role-Key gehören ausschließlich in die
Supabase-Secrets — niemals in dieses Repository.
