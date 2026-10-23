# Disponenten-Simulator

Browserbasiertes Leitstellen-/Feuerwehr-Spiel. Das ganze Spiel steckt in `index.html`
(Leaflet/OSRM, alles per CDN), das Backend ist Supabase (`db/supabase_setup.sql`).
Gehostet über GitHub Pages direkt aus `main`.

## Arbeitsweise

- **Niemals direkt auf `main` committen oder pushen.** Jede Änderung kommt auf einen eigenen
  Branch und wird immer zuerst als Pull Request gegen `main` gestellt.
- Erst nach Freigabe durch den Repo-Inhaber wird der Pull Request gemergt.
- Keine geheimen Schlüssel (Service-Role-Key o. Ä.) ins Repository — in `index.html` stehen nur
  die öffentliche Supabase-URL und der Anon-Key.
