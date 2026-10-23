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

## Rechtliches und Socials

- `seiten/impressum.html`, `seiten/datenschutz.html`, `seiten/socials.html` (gemeinsames Aussehen in `seiten/seiten.css`)
- Verlinkt auf dem Login-Bildschirm, im Wartungsbildschirm und im Menü (☰) im Spiel.
- Social-Links trägt man oben im Script von `seiten/socials.html` in die Liste `SOCIALS` ein (leere `url` = „folgt bald“).
- Kommt der Shop mit Zahlungen dazu, müssen Impressum und Datenschutzerklärung angepasst werden.

## Rettungsdienst und Patienten

- `daten/rd_codes.js`: AMPDS-Stichwörter der Berliner Feuerwehr (BF-Open-Data, CC BY 4.0) für reine RD-Einsätze
- `daten/kliniken.js`: 38 Berliner Krankenhäuser der Notfallversorgung, Fachabteilungen aus dem Krankenhausplan 2020 (Anlage 1)
- Sonderfahrzeuge: STEMO (Schlaganfall, ersetzt dort den Notarzt), KdoW LNA (ab 3 Patienten), GW-San/AB-MANV (ab 4 Patienten), NKTW (Patienten ohne Notarzt)
- Ablauf: RTW versorgt vor Ort (bei Notarzt-Indikation zusätzlich NEF) → Status 5 → Krankenhaus wählen → Status 7/8 → frei
- Einstellungen dazu stehen in `CONFIG` (rdShare, treatMinutes, handoverMinutes, transportBase, transportPerKm, naBonus)

## Einsatzkatalog

- 326 Feuerwehr-Einsätze aus 164 Szenarien, erzeugt mit `werkzeuge/einsatzkatalog.py` (Szenarien dort anpassen und das Skript ausführen)
- Stichwörter nach dem öffentlichen Aufbau der Berliner AAO: Kategorie **BRAND** bzw. **TH** mit Alarmstufe (TH 0 = kleine Hilfeleistung). Die tatsächlichen Berliner Stichwortlisten sind als VS-NfD eingestuft und werden nicht verwendet.
- Polizei und THW werden (noch) nicht benötigt.
