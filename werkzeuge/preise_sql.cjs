// Überträgt die Preise aus index.html (CONFIG, VEHICLES) in den Preisblock von db/supabase_setup.sql.
// Der Server braucht sie, um Spielstände zu prüfen (Anti-Cheat in app_save).
// Aufruf nach jeder Preisänderung:  node werkzeuge/preise_sql.cjs
const fs = require('fs'), path = require('path');
const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const grab = (re, name) => { const m = html.match(re); if (!m) throw new Error(name + ' nicht gefunden'); return m[1]; };
const CONFIG = eval('(' + grab(/const CONFIG = (\{[\s\S]*?\n\});/, 'CONFIG') + ')');
const VEHICLES = JSON.parse(grab(/const VEHICLES = (\{.*\});/, 'VEHICLES'));

const rows = [];
for (const v of Object.values(VEHICLES)) rows.push(['vehicle', v.id, v.cost]);
// Umbenannte Typen alter Spielstände behalten den Preis des Nachfolgers (sonst Fehlalarm beim Umstieg)
const LEGACY_TYPES = { lhf10: 'lhf16' };
for (const [alt, neu] of Object.entries(LEGACY_TYPES)) rows.push(['vehicle', alt, VEHICLES[neu].cost]);
// Wache Level n: günstigster legaler Weg = direkt mit n Ausbaustufen bauen (mit Rabatt)
for (let n = 1; n <= CONFIG.maxStationLevel; n++) {
  let up = 0; for (let l = 1; l < n; l++) up += CONFIG.upgradeCost(l);
  const disc = Math.min(CONFIG.bulkDiscountMax, CONFIG.bulkDiscountPerLevel * (n - 1));
  rows.push(['station', 'L' + n, CONFIG.stationBuildCost + Math.round(up * (1 - disc))]);
}
for (let n = 1; n <= CONFIG.maxAcademyLevel; n++) {
  let c = CONFIG.academyBuildCost; for (let l = 1; l < n; l++) c += CONFIG.academyUpgradeCost(l);
  rows.push(['academy', 'L' + n, c]);
}
rows.push(['cfg', 'startCredits', CONFIG.startCredits]);

const block = '-- PREISE:BEGIN (automatisch erzeugt mit: node werkzeuge/preise_sql.cjs, nicht von Hand ändern)\n'
  + 'delete from app_prices;\ninsert into app_prices(kind, id, price) values\n'
  + rows.map(([k, i, p]) => `  ('${k}','${i}',${p})`).join(',\n') + ';\n-- PREISE:END';
const file = path.join(root, 'db', 'supabase_setup.sql');
const sql = fs.readFileSync(file, 'utf8');
const re = /-- PREISE:BEGIN[\s\S]*?-- PREISE:END/;
if (!re.test(sql)) throw new Error('Preisblock in supabase_setup.sql fehlt');
fs.writeFileSync(file, sql.replace(re, block));
console.log(`${rows.length} Preise geschrieben`);
