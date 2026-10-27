// Überträgt die Preise aus index.html (CONFIG, VEHICLES) in den Preisblock von db/supabase_setup.sql,
// dazu Forschungen (RESEARCH) und Quests (QUESTS) in den Shop-Datenblock.
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
let out = sql.replace(re, block);

// Shop-Daten: Forschungen und Quests (der Server prüft damit Kosten, Dauer, Voraussetzungen und Belohnungen)
const RESEARCH = JSON.parse(grab(/const RESEARCH = (\[.*\]);/, 'RESEARCH'));
const QUESTS = JSON.parse(grab(/const QUESTS = (\[.*\]);/, 'QUESTS'));
const q = v => v == null ? 'null' : `'${String(v).replace(/'/g, "''")}'`;
const shop = '-- SHOPDATEN:BEGIN (automatisch erzeugt mit: node werkzeuge/preise_sql.cjs, nicht von Hand ändern)\n'
  + 'delete from app_research_nodes;\ninsert into app_research_nodes(id, max_level, premium_from, rp, minutes, req) values\n'
  + RESEARCH.map(r => `  (${q(r.id)},${r.max},${r.premiumFrom == null ? 'null' : r.premiumFrom},${r.rp},${r.min},${q(r.req)})`).join(',\n') + ';\n'
  + 'delete from app_quests where id not in (select quest from app_quest_claims);\n'
  + 'insert into app_quests(id, period, premium, money, rp, ep, counter, goal) values\n'
  + QUESTS.map(x => `  (${q(x.id)},${q(x.period)},${x.premium},${x.money},${x.rp},${x.ep || 0},${q(x.counter)},${x.goal})`).join(',\n')
  + '\non conflict (id) do update set period=excluded.period, premium=excluded.premium, money=excluded.money, rp=excluded.rp, ep=excluded.ep, counter=excluded.counter, goal=excluded.goal;\n-- SHOPDATEN:END';
const reShop = /-- SHOPDATEN:BEGIN[\s\S]*?-- SHOPDATEN:END/;
if (!reShop.test(out)) throw new Error('Shop-Datenblock in supabase_setup.sql fehlt');
out = out.replace(reShop, shop);
fs.writeFileSync(file, out);
console.log(`${rows.length} Preise, ${RESEARCH.length} Forschungen, ${QUESTS.length} Quests geschrieben`);
