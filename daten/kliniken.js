/* Berliner Krankenhäuser mit Teilnahme an der Notfallversorgung.
   Quelle Fachabteilungen: Krankenhausplan 2020 des Landes Berlin (Senatsverwaltung für Gesundheit), Anlage 1 „Datenblätter“
   (Stand der Datenblätter 01.10.2020, Großgeräte 31.07.2019):
     inn  Innere Medizin                       unf  Chirurgie / Orthopädie-Unfallchirurgie
     kar  Linksherzkathetermessplatz vorhanden str  Stroke Unit (Fußnote „darunter Stroke Unit“)
     geb  Frauenheilkunde und Geburtshilfe      kin  Kinder- und Jugendheilkunde
     psy  Psychiatrie und Psychotherapie        bra  Betten für Schwerbrandverletzte
   nz = Notfallzentrum (sonst Notfallkrankenhaus). Koordinaten: OpenStreetMap/Nominatim (ODbL). */
const DEPTS={"inn":"Innere Medizin","unf":"Unfallchirurgie","kar":"Herzkatheter","str":"Stroke Unit","geb":"Geburtshilfe","kin":"Kinderklinik","psy":"Psychiatrie","bra":"Brandverletzte"};
const HOSPITALS=[
{"id": "kh01", "name": "Alexianer St. Hedwig-Krankenhaus", "lat": 52.52594, "lng": 13.39836, "nz": false, "dept": ["inn", "unf", "psy"]},
{"id": "kh02", "name": "Alexianer Krankenhaus Hedwigshöhe", "lat": 52.40615, "lng": 13.56998, "nz": false, "dept": ["inn", "unf", "psy"]},
{"id": "kh03", "name": "BG Klinikum Unfallkrankenhaus Berlin (ukb)", "lat": 52.51917, "lng": 13.56832, "nz": true, "dept": ["inn", "unf", "kar", "str", "bra"]},
{"id": "kh04", "name": "Bundeswehrkrankenhaus Berlin", "lat": 52.53567, "lng": 13.37139, "nz": false, "dept": ["inn", "unf", "str", "psy"]},
{"id": "kh05", "name": "Caritas-Klinik Dominikus", "lat": 52.62471, "lng": 13.29408, "nz": false, "dept": ["inn", "unf"]},
{"id": "kh06", "name": "Caritas-Klinik Maria Heimsuchung", "lat": 52.57102, "lng": 13.41414, "nz": false, "dept": ["inn", "unf", "geb"]},
{"id": "kh07", "name": "Charité – Campus Benjamin Franklin", "lat": 52.44075, "lng": 13.31703, "nz": true, "dept": ["inn", "unf", "kar", "str", "geb", "psy"]},
{"id": "kh08", "name": "Charité – Campus Mitte", "lat": 52.52585, "lng": 13.37776, "nz": false, "dept": ["inn", "unf", "kar", "str", "geb", "kin", "psy"]},
{"id": "kh09", "name": "Charité – Campus Virchow-Klinikum", "lat": 52.54223, "lng": 13.34735, "nz": true, "dept": ["inn", "unf", "kar", "str", "geb", "kin"]},
{"id": "kh10", "name": "DRK Kliniken Berlin Köpenick", "lat": 52.43975, "lng": 13.59403, "nz": false, "dept": ["inn", "unf", "str", "geb"]},
{"id": "kh11", "name": "DRK Kliniken Berlin Mitte", "lat": 52.5574, "lng": 13.37574, "nz": false, "dept": ["inn", "unf"]},
{"id": "kh12", "name": "DRK Kliniken Berlin Westend", "lat": 52.52066, "lng": 13.27755, "nz": false, "dept": ["inn", "unf", "kar", "geb", "kin"]},
{"id": "kh13", "name": "Ev. Elisabeth Klinik", "lat": 52.50364, "lng": 13.365, "nz": false, "dept": ["inn", "unf"]},
{"id": "kh14", "name": "Ev. Krankenhaus Hubertus", "lat": 52.42992, "lng": 13.22062, "nz": false, "dept": ["inn", "unf"]},
{"id": "kh15", "name": "Ev. Krankenhaus Königin Elisabeth Herzberge", "lat": 52.52792, "lng": 13.50899, "nz": false, "dept": ["inn", "unf", "str", "psy"]},
{"id": "kh16", "name": "Ev. Waldkrankenhaus Spandau", "lat": 52.563, "lng": 13.15694, "nz": false, "dept": ["inn", "unf", "geb", "kin"]},
{"id": "kh17", "name": "Franziskus-Krankenhaus", "lat": 52.5064, "lng": 13.34535, "nz": false, "dept": ["inn", "unf"]},
{"id": "kh18", "name": "Gemeinschaftskrankenhaus Havelhöhe", "lat": 52.46373, "lng": 13.1637, "nz": false, "dept": ["inn", "unf", "kar", "geb"]},
{"id": "kh19", "name": "Helios Klinikum Berlin-Buch", "lat": 52.63056, "lng": 13.50952, "nz": true, "dept": ["inn", "unf", "kar", "str", "geb", "kin"]},
{"id": "kh20", "name": "Helios Klinikum Emil von Behring", "lat": 52.4227, "lng": 13.25535, "nz": false, "dept": ["inn", "unf", "kar", "kin"]},
{"id": "kh21", "name": "Jüdisches Krankenhaus Berlin", "lat": 52.55538, "lng": 13.37021, "nz": false, "dept": ["inn", "unf", "kar", "str", "psy"]},
{"id": "kh22", "name": "Krankenhaus Bethel Berlin", "lat": 52.43243, "lng": 13.3266, "nz": false, "dept": ["inn", "unf"]},
{"id": "kh23", "name": "Krankenhaus Waldfriede", "lat": 52.44448, "lng": 13.2401, "nz": false, "dept": ["inn", "unf", "geb"]},
{"id": "kh24", "name": "Martin-Luther-Krankenhaus", "lat": 52.49127, "lng": 13.29132, "nz": false, "dept": ["inn", "unf", "geb"]},
{"id": "kh25", "name": "Park-Klinik Weißensee", "lat": 52.55492, "lng": 13.45185, "nz": false, "dept": ["inn", "unf", "str", "geb"]},
{"id": "kh26", "name": "Sana Klinikum Lichtenberg", "lat": 52.51328, "lng": 13.4959, "nz": false, "dept": ["inn", "unf", "kar", "geb", "kin"]},
{"id": "kh27", "name": "Schlosspark-Klinik", "lat": 52.52223, "lng": 13.28899, "nz": false, "dept": ["inn", "unf", "kar", "str", "psy"]},
{"id": "kh28", "name": "St. Gertrauden-Krankenhaus", "lat": 52.48017, "lng": 13.31646, "nz": false, "dept": ["inn", "unf", "geb"]},
{"id": "kh29", "name": "St. Joseph Krankenhaus Tempelhof", "lat": 52.47814, "lng": 13.37295, "nz": false, "dept": ["inn", "unf", "geb", "kin"]},
{"id": "kh30", "name": "St. Marien Krankenhaus", "lat": 52.42361, "lng": 13.35139, "nz": false, "dept": ["inn", "unf"]},
{"id": "kh31", "name": "Vivantes Klinikum im Friedrichshain", "lat": 52.52452, "lng": 13.44063, "nz": true, "dept": ["inn", "unf", "kar", "str", "geb", "kin", "psy"]},
{"id": "kh32", "name": "Vivantes Klinikum Am Urban", "lat": 52.49392, "lng": 13.40862, "nz": false, "dept": ["inn", "unf", "kar", "geb", "psy"]},
{"id": "kh33", "name": "Vivantes Klinikum Kaulsdorf", "lat": 52.50744, "lng": 13.59219, "nz": false, "dept": ["inn", "unf", "geb", "psy"]},
{"id": "kh34", "name": "Vivantes Klinikum Neukölln", "lat": 52.43722, "lng": 13.45922, "nz": true, "dept": ["inn", "unf", "kar", "str", "geb", "kin", "psy"]},
{"id": "kh35", "name": "Vivantes Auguste-Viktoria-Klinikum", "lat": 52.46349, "lng": 13.34581, "nz": false, "dept": ["inn", "unf", "str", "geb", "psy"]},
{"id": "kh36", "name": "Vivantes Wenckebach-Klinikum", "lat": 52.45899, "lng": 13.39024, "nz": false, "dept": ["inn", "unf", "psy"]},
{"id": "kh37", "name": "Vivantes Humboldt-Klinikum", "lat": 52.59018, "lng": 13.30476, "nz": false, "dept": ["inn", "unf", "kar", "str", "geb", "psy"]},
{"id": "kh38", "name": "Vivantes Klinikum Spandau", "lat": 52.54906, "lng": 13.20621, "nz": false, "dept": ["inn", "unf", "str", "psy"]}
];
