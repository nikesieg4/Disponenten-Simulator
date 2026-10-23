# Disponenten-Simulator (Leitstelle)

Ein browserbasiertes Leitstellen-/Feuerwehr-Dispositionsspiel als **einzelne `index.html`** —
Karte (Leaflet/OpenStreetMap), echte Straßen-Routen (OSRM), FMS-Funkstatus, Wachen,
Fahrzeuge, Personal, Lehrgänge und Einsätze.

Backend: **Supabase** (Login, Spielstände). Der Shop ist noch nicht verfügbar. In der `index.html` stehen nur die öffentliche Supabase-URL und
der Anon-Key (durch RLS geschützt) — **keine** geheimen Schlüssel.

## Hosting (GitHub Pages)

Die `index.html` liegt im Hauptverzeichnis. Unter **Settings → Pages** als Quelle
„Deploy from a branch", Branch `main`, Ordner `/ (root)` wählen. Danach ist das Spiel
unter `https://<user>.github.io/disponenten-simulator/` erreichbar.

Die Seite ist in sich geschlossen (alle Bibliotheken per HTTPS-CDN) und läuft von jeder
Domain — ein Wechsel des Hosters erfordert keine Code-Änderung.

## Einrichtung des Backends

1. Supabase-Projekt anlegen.
2. `db/supabase_setup.sql` im Supabase SQL-Editor ausführen (Tabellen, Login, Bann/Wartung/Flagging).
   Bei einer bestehenden Installation entfernt das Skript auch das frühere Administrator-Konto
   sowie die alten Admin- und Shop-Funktionen/-Tabellen.
3. In `index.html` oben `SUPABASE_URL` und `SUPABASE_ANON_KEY` eintragen (bereits gesetzt).
