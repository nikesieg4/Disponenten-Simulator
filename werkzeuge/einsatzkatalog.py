"""Erzeugt den Einsatzkatalog (MISSION_TYPES) in index.html.

Szenarien unten in S anpassen, dann ausführen:  python3 werkzeuge/einsatzkatalog.py
Aufbau der Stichwörter nach dem öffentlichen Schema der Berliner AAO (Kategorie BRAND/TH + Alarmstufe);
die Fahrzeuge je Stufe sind eigene Festlegungen, nicht die (nicht öffentliche) Berliner AAO.
"""
import json,re,unicodedata
# ---------- Fahrzeuggruppen ----------
G={
 'LOESCH':(['hlf20','lhf16','lf20','lfkats','lf16ts'],'LHF/LF'),
 'TLF':(['tlf','tlf3000','tlf4000','tlf1624','tlf2024','tlf2450cafs'],'TLF'),
 'DLK':(['dlk','tm50'],'DLK'),
 'ELWC':(['elw1c'],'ELW 1 C'), 'ELWB':(['elw1b'],'ELW 1 B'), 'ELW2':(['elw2'],'ELW 2'), 'KDOW':(['kdow'],'KdoW'),
 'RW':(['rw'],'RW'), 'GWA':(['gw_a','ab_atemschutz'],'GW-A/AB-A'), 'GWG':(['gw_g','ab_gefahrgut'],'GW-G/AB-G'),
 'MESS':(['gw_mess'],'GW-Mess'), 'DEKON':(['gw_dekonp','ab_dekon'],'Dekon'), 'LUEFT':(['ab_lueft','fwa_vent'],'Lüfter'),
 'OEL':(['ab_auffang'],'AB-Auffang'), 'SCHAUM':(['ab_schaum','ab_sonderl','tlf2450cafs','tlf2024'],'Schaum/CAFS'),
 'SCHLAUCH':(['sw2000','swkats','ab_schlauch'],'Schlauch'), 'KRAN':(['fwk'],'FwK'), 'HOEHE':(['gw_hoehe'],'GW-Höhe'),
 'TAUCH':(['gw_taucher'],'GW-Taucher'), 'BOOT':(['mzb','gw_wr'],'Boot/GW-W'), 'NEA':(['fwa_notstrom'],'Notstrom'),
 'KLEIN':(['klef','hlf20','lhf16','lf20','lfkats','lf16ts'],'KLEF/LHF'), 'TM':(['tm50'],'TM 50'), 'WLF':(['wlf'],'WLF'),
}
def R(grp,n=1):
    t,l=G[grp]; return {'count':n,'types':t,'label':l}
# ---------- Grundaufgebot je Kategorie und Alarmstufe ----------
def base(kind,lvl):
    req=[];m=0;w=0;f=0
    if kind=='geb':   # Gebäudebrand
        L={1:1,2:2,3:3,4:5,5:7,6:9}[lvl]; req=[R('LOESCH',L)]
        if lvl>=2: req+= [R('ELWC'),R('DLK',1 if lvl<4 else 2)]
        if lvl>=3: req+= [R('ELWB'),R('GWA')]
        if lvl>=4: req+= [R('LUEFT')]
        if lvl>=5: req+= [R('ELW2'),R('KDOW'),R('SCHLAUCH')]
        if lvl>=6: req+= [R('TLF',2),R('GWA',2)]
        m={1:20,2:50,3:90,4:150,5:240,6:330}[lvl]; w={1:0,2:800,3:2400,4:5000,5:9000,6:14000}[lvl]
    elif kind=='frei':  # Brand im Freien / Vegetation / Container
        L={1:1,2:2,3:3,4:5,5:7}[lvl]; req=[R('LOESCH',L)]
        if lvl>=2: req+= [R('ELWC')]
        if lvl>=3: req+= [R('TLF'),R('ELWB')]
        if lvl>=4: req+= [R('TLF',2),R('SCHLAUCH')]
        if lvl>=5: req+= [R('ELW2'),R('KDOW'),R('TLF',3)]
        m={1:20,2:40,3:80,4:150,5:240}[lvl]; w={1:300,2:1200,3:4000,4:9000,5:16000}[lvl]
    elif kind=='fzg':   # Fahrzeugbrand
        L={1:1,2:2,3:3,4:4}[lvl]; req=[R('LOESCH',L)]
        if lvl>=2: req+= [R('ELWC')]
        if lvl>=3: req+= [R('TLF'),R('GWA')]
        if lvl>=4: req+= [R('ELWB'),R('SCHAUM')]
        m={1:25,2:45,3:80,4:130}[lvl]; w={1:600,2:1500,3:4000,4:7000}[lvl]; f={1:0,2:150,3:400,4:1000}[lvl]
    elif kind=='th':    # Technische Hilfeleistung
        L={1:1,2:2,3:3,4:5}[lvl]; req=[R('LOESCH',L)]
        if lvl>=2: req+= [R('RW'),R('ELWC')]
        if lvl>=3: req+= [R('ELWB')]
        if lvl>=4: req+= [R('RW',2),R('KDOW')]
        m={1:25,2:60,3:120,4:200}[lvl]
    elif kind=='klein': # Kleine Hilfeleistung
        req=[R('KLEIN')]; m=20
    elif kind=='gsg':   # Gefahrstoffe
        L={1:1,2:2,3:3,4:5}[lvl]; req=[R('LOESCH',L)]
        if lvl>=1: req+= [R('MESS')] if lvl>=2 else []
        if lvl>=2: req+= [R('ELWC'),R('GWG')]
        if lvl>=3: req+= [R('ELWB'),R('DEKON'),R('GWA')]
        if lvl>=4: req+= [R('ELW2'),R('LUEFT')]
        m={1:30,2:80,3:150,4:240}[lvl]
    elif kind=='wasser':
        req=[R('LOESCH'),R('BOOT')]
        if lvl>=2: req+= [R('TAUCH'),R('ELWC')]
        if lvl>=3: req+= [R('BOOT',2),R('LOESCH',2),R('ELWB')]
        m={1:40,2:80,3:150}[lvl]
    return req,m,w,f
# ---------- Szenarien: (Name, Art, Alarmstufen, Zusätze, Patienten [min,max,NA-Anteil,Fachabteilung], Häufigkeit) ----------
P0=None
S=[
# Gebäudebrände
("Rauchentwicklung aus Wohnung",'geb',[1,2],{},[0,1,.2,'inn'],5),
("Brennendes Essen auf Herd",'geb',[1,2],{},[0,1,.1,'bra'],7),
("Zimmerbrand",'geb',[2,3],{},[0,2,.3,'inn'],6),
("Küchenbrand",'geb',[2,3],{},[0,2,.2,'bra'],5),
("Wohnungsbrand",'geb',[3,4],{},[1,3,.4,'inn'],5),
("Wohnungsbrand, Menschenleben in Gefahr",'geb',[3,4],{3:['DLK']},[1,4,.5,'inn'],3),
("Kellerbrand",'geb',[2,3,4],{3:['LUEFT']},[0,2,.3,'inn'],5),
("Dachstuhlbrand",'geb',[3,4,5],{},[0,2,.3,'inn'],3),
("Brand im Treppenhaus",'geb',[2,3,4],{},[1,4,.4,'inn'],3),
("Brennender Balkon",'geb',[2,3],{},[0,1,.2,'inn'],4),
("Brand in Mehrfamilienhaus",'geb',[3,4,5],{},[1,5,.5,'inn'],3),
("Brand in Einfamilienhaus",'geb',[3,4],{},[0,3,.4,'inn'],3),
("Brand in Reihenhaus",'geb',[3,4],{},[0,3,.4,'inn'],3),
("Hochhausbrand",'geb',[4,5,6],{4:['GWA','LUEFT'],5:['TM']},[2,6,.5,'inn'],1),
("Brand in Gartenlaube",'geb',[1,2],{},[0,1,.2,'bra'],5),
("Brennender Schuppen",'geb',[1,2],{},[0,0,0,'inn'],5),
("Garagenbrand",'geb',[1,2,3],{},[0,1,.2,'inn'],5),
("Tiefgaragenbrand",'geb',[3,4,5],{3:['LUEFT','GWA']},[0,3,.3,'inn'],2),
("Brand in Schule",'geb',[3,4,5],{},[0,4,.3,'inn'],2),
("Brand in Kita",'geb',[3,4],{},[1,5,.4,'kin'],1),
("Brand in Krankenhaus",'geb',[4,5,6],{},[2,6,.6,'inn'],1),
("Brand in Pflegeheim",'geb',[4,5],{},[2,6,.6,'inn'],1),
("Brand in Hotel",'geb',[3,4,5],{},[1,5,.4,'inn'],2),
("Brand in Gaststätte",'geb',[2,3,4],{},[0,3,.3,'bra'],3),
("Brand in Supermarkt",'geb',[3,4,5],{},[0,3,.3,'inn'],2),
("Brand in Einkaufszentrum",'geb',[4,5,6],{},[1,6,.4,'inn'],1),
("Brand in Bürogebäude",'geb',[3,4,5],{},[0,4,.3,'inn'],2),
("Brand in Lagerhalle",'geb',[3,4,5],{4:['TLF','SCHLAUCH']},[0,2,.3,'unf'],2),
("Brand in Werkstatt",'geb',[2,3,4],{},[0,2,.3,'bra'],3),
("Brand in Tischlerei",'geb',[3,4,5],{},[0,2,.3,'bra'],2),
("Brand in Industriebetrieb",'geb',[4,5,6],{4:['SCHAUM','TLF']},[0,4,.4,'bra'],1),
("Brand in Kirche",'geb',[3,4,5],{3:['TM']},[0,2,.2,'inn'],1),
("Brand in Museum",'geb',[3,4,5],{},[0,2,.2,'inn'],1),
("Brand in Theater",'geb',[4,5],{},[1,5,.4,'inn'],1),
("Brand in Sporthalle",'geb',[3,4],{},[0,3,.3,'inn'],2),
("Brand in Kleingartenanlage",'geb',[2,3,4],{},[0,1,.2,'bra'],3),
("Brand in Bahnhofsgebäude",'geb',[3,4,5],{},[0,4,.3,'inn'],1),
("Brand in U-Bahnhof",'geb',[4,5,6],{4:['LUEFT','GWA']},[1,6,.5,'inn'],1),
("Brand in Studentenwohnheim",'geb',[3,4,5],{},[1,5,.4,'inn'],2),
("Brand in Asylunterkunft",'geb',[3,4,5],{},[1,6,.4,'inn'],1),
("Brand in Rohbau",'geb',[2,3],{},[0,1,.2,'unf'],3),
("Brand in leerstehendem Gebäude",'geb',[2,3,4],{},[0,1,.2,'inn'],3),
("Brand in Müllraum",'geb',[1,2],{},[0,1,.1,'inn'],5),
("Brennender Aufzugsschacht",'geb',[2,3],{},[0,2,.3,'inn'],2),
("Schornsteinbrand",'geb',[1,2],{2:['DLK']},[0,0,0,'inn'],4),
("Brandmeldeanlage",'geb',[2,3],{},[0,0,0,'inn'],8),
("Heimrauchmelder ausgelöst",'geb',[1],{},[0,1,.2,'inn'],8),
("Brandgeruch im Gebäude",'geb',[1,2],{},[0,0,0,'inn'],6),
("Brand in Trafostation",'geb',[2,3],{2:['NEA']},[0,1,.3,'bra'],2),
("Brand in Photovoltaikanlage",'geb',[2,3],{2:['DLK']},[0,0,0,'inn'],2),
("Brand in Kühlhaus",'geb',[3,4],{3:['GWA','LUEFT']},[0,2,.3,'inn'],1),
("Brand in Parkhaus",'geb',[3,4,5],{3:['LUEFT']},[0,2,.3,'inn'],2),
("Brand in Recyclinghof",'frei',[3,4,5],{3:['SCHAUM']},[0,1,.2,'inn'],2),
# Brände im Freien
("Mülltonnenbrand",'frei',[1],{},[0,0,0,'inn'],10),
("Containerbrand",'frei',[1,2],{},[0,0,0,'inn'],7),
("Brennender Papierkorb",'frei',[1],{},[0,0,0,'inn'],8),
("Brennender Sperrmüll",'frei',[1,2],{},[0,0,0,'inn'],6),
("Brennende Hecke",'frei',[1,2],{},[0,0,0,'inn'],6),
("Brennender Baum",'frei',[1,2],{2:['DLK']},[0,0,0,'inn'],5),
("Flächenbrand",'frei',[2,3,4],{},[0,1,.2,'bra'],4),
("Wiesenbrand",'frei',[1,2,3],{},[0,0,0,'inn'],5),
("Waldbrand",'frei',[3,4,5],{},[0,2,.3,'bra'],2),
("Böschungsbrand an der Bahn",'frei',[2,3],{},[0,0,0,'inn'],3),
("Brennender Strohballen",'frei',[1,2],{},[0,0,0,'inn'],3),
("Brand auf Baustelle",'frei',[2,3],{},[0,1,.2,'unf'],3),
("Brennendes Lagerfeuer",'frei',[1],{},[0,0,0,'inn'],5),
("Brennender Holzstapel",'frei',[1,2],{},[0,0,0,'inn'],4),
("Brennende Mülldeponie",'frei',[3,4,5],{3:['SCHAUM']},[0,1,.2,'inn'],1),
("Silvester-Brand",'frei',[1,2],{},[0,1,.2,'bra'],4),
("Brennender Kinderwagen im Hausflur",'geb',[1,2],{},[0,2,.2,'inn'],3),
# Fahrzeugbrände
("PKW-Brand",'fzg',[1,2],{},[0,1,.2,'bra'],8),
("Brennendes Motorrad",'fzg',[1],{},[0,1,.2,'bra'],4),
("Brennender Motorroller",'fzg',[1],{},[0,0,0,'inn'],4),
("E-Auto-Brand",'fzg',[2,3],{2:['SCHAUM']},[0,1,.2,'bra'],3),
("Brennender E-Scooter",'fzg',[1],{},[0,0,0,'inn'],5),
("Brennender Transporter",'fzg',[2,3],{},[0,1,.2,'bra'],4),
("LKW-Brand",'fzg',[2,3,4],{},[0,1,.3,'bra'],3),
("Busbrand",'fzg',[3,4],{3:['GWA']},[0,4,.3,'bra'],2),
("Brennender Wohnwagen",'fzg',[1,2],{},[0,1,.2,'bra'],3),
("Brennendes Boot",'fzg',[2,3],{2:['BOOT']},[0,1,.3,'bra'],2),
("Brand in U-Bahn-Zug",'fzg',[3,4],{3:['LUEFT','GWA']},[1,6,.4,'inn'],1),
("Brennender Gefahrgut-LKW",'fzg',[3,4],{3:['MESS','GWG','SCHAUM']},[0,2,.4,'bra'],1),
("Brennender Tankwagen",'fzg',[4],{4:['MESS','GWG','SCHAUM','TLF']},[0,2,.5,'bra'],1),
("Mehrere PKW in Brand",'fzg',[2,3],{},[0,1,.2,'bra'],3),
("Brennender Müllwagen",'fzg',[2,3],{},[0,1,.2,'bra'],2),
("Brennende Straßenbahn",'fzg',[3,4],{},[0,4,.3,'inn'],1),
# Technische Hilfeleistung
("Verkehrsunfall",'th',[1,2],{},[1,2,.3,'unf'],10),
("Verkehrsunfall mit eingeklemmter Person",'th',[2,3],{},[1,2,1,'unf'],5),
("Verkehrsunfall mit mehreren Fahrzeugen",'th',[2,3,4],{},[2,5,.5,'unf'],3),
("Motorradunfall",'th',[1,2],{},[1,1,.6,'unf'],5),
("Fahrradunfall",'th',[1],{},[1,1,.2,'unf'],5),
("Verkehrsunfall mit Bus",'th',[3,4],{},[2,6,.5,'unf'],1),
("Verkehrsunfall mit LKW",'th',[2,3],{3:['KRAN']},[1,2,.5,'unf'],3),
("Verkehrsunfall mit Straßenbahn",'th',[2,3],{},[1,3,.5,'unf'],2),
("PKW in Gewässer",'th',[3],{3:['BOOT','TAUCH']},[1,2,.8,'inn'],1),
("PKW auf Dach",'th',[2],{},[1,1,.5,'unf'],3),
("Fahrzeug in Gebäude",'th',[2,3],{3:['KRAN']},[1,2,.4,'unf'],2),
("Person unter U-Bahn",'th',[3],{},[1,1,1,'unf'],1),
("Person unter Straßenbahn",'th',[3],{},[1,1,1,'unf'],1),
("Person eingeklemmt",'th',[2],{},[1,1,1,'unf'],3),
("Person in Aufzug",'th',[1],{},[0,1,0,'inn'],8),
("Person in Notlage",'th',[1,2],{},[1,1,.3,'inn'],6),
("Hilflose Person hinter Tür",'th',[1],{},[1,1,.3,'inn'],8),
("Türöffnung für den Rettungsdienst",'klein',[1],{},[1,1,.3,'inn'],8),
("Person auf Dach",'th',[2],{2:['DLK']},[0,1,.3,'psy'],2),
("Person droht zu springen",'th',[2,3],{2:['DLK']},[1,1,.5,'psy'],2),
("Person in Höhe",'th',[2,3],{2:['DLK'],3:['HOEHE']},[1,1,.4,'unf'],2),
("Person in Tiefe",'th',[2,3],{3:['HOEHE']},[1,1,.5,'unf'],2),
("Person auf Kran",'th',[3],{3:['HOEHE']},[1,1,.4,'unf'],1),
("Person in Schacht",'th',[2,3],{3:['HOEHE','GWA']},[1,1,.5,'unf'],2),
("Person verschüttet",'th',[3,4],{3:['KRAN']},[1,2,.8,'unf'],1),
("Bauunfall",'th',[2,3],{3:['KRAN']},[1,2,.6,'unf'],2),
("Gerüsteinsturz",'th',[3,4],{3:['KRAN','HOEHE']},[1,4,.5,'unf'],1),
("Gebäudeeinsturz",'th',[4],{4:['KRAN','HOEHE']},[2,6,.6,'unf'],1),
("Einsturzgefahr",'th',[2,3],{},[0,0,0,'inn'],2),
("Baum auf Straße",'th',[1,2],{},[0,0,0,'inn'],7),
("Baum auf Fahrzeug",'th',[2],{},[0,1,.3,'unf'],3),
("Baum auf Dach",'th',[2,3],{2:['DLK'],3:['KRAN']},[0,0,0,'inn'],3),
("Ast droht abzustürzen",'th',[1,2],{2:['DLK']},[0,0,0,'inn'],6),
("Sturmschaden",'th',[1,2],{2:['DLK']},[0,0,0,'inn'],6),
("Dachziegel droht abzustürzen",'th',[1,2],{1:['DLK']},[0,0,0,'inn'],5),
("Fassadenteile drohen abzustürzen",'th',[2],{2:['DLK']},[0,0,0,'inn'],3),
("Wasserrohrbruch",'th',[1,2],{},[0,0,0,'inn'],7),
("Wasser im Keller",'th',[1,2],{},[0,0,0,'inn'],8),
("Überflutete Straße",'th',[1,2],{},[0,0,0,'inn'],4),
("Unwetter mit überfluteten Kellern",'th',[2,3],{3:['NEA']},[0,0,0,'inn'],2),
("Ölspur",'klein',[1],{},[0,0,0,'inn'],10),
("Großflächige Ölspur",'th',[2],{2:['OEL']},[0,0,0,'inn'],3),
("Auslaufende Betriebsstoffe",'th',[1,2],{2:['OEL']},[0,0,0,'inn'],5),
("Tier in Not",'klein',[1],{},[0,0,0,'inn'],8),
("Katze auf Baum",'th',[1],{1:['DLK']},[0,0,0,'inn'],5),
("Pferd in Graben",'th',[2],{2:['KRAN']},[0,0,0,'inn'],2),
("Schwan auf Eis",'wasser',[1],{},[0,0,0,'inn'],2),
("Tier im Kanal",'th',[1],{},[0,0,0,'inn'],3),
("Insektennest",'klein',[1],{},[0,0,0,'inn'],5),
("Ring an Finger",'klein',[1],{},[1,1,0,'unf'],4),
("Hand in Maschine",'th',[2],{},[1,1,.6,'unf'],2),
("Person in Maschine",'th',[3],{},[1,1,1,'unf'],1),
("Arbeitsunfall",'th',[1,2],{},[1,1,.5,'unf'],4),
("Rettung aus Rolltreppe",'th',[2],{},[1,1,.4,'unf'],2),
("Kind in Not",'th',[1,2],{},[1,1,.4,'kin'],3),
("Stromausfall in Pflegeheim",'th',[2],{2:['NEA']},[0,2,.2,'inn'],2),
("Notstromversorgung Krankenhaus",'th',[2],{2:['NEA']},[0,0,0,'inn'],1),
("Gasgeruch",'gsg',[1,2],{},[0,1,.2,'inn'],7),
("Gasausströmung",'gsg',[2,3],{},[0,2,.4,'inn'],3),
("CO-Melder ausgelöst",'gsg',[1,2],{2:['MESS']},[0,2,.3,'inn'],6),
("Kohlenmonoxidvergiftung",'gsg',[2],{},[1,3,.6,'inn'],2),
("Unklarer Geruch",'gsg',[1,2],{},[0,0,0,'inn'],5),
("Austritt von Gefahrstoffen",'gsg',[2,3,4],{},[0,3,.4,'inn'],2),
("Gefahrgutunfall",'gsg',[3,4],{3:['RW']},[1,3,.5,'unf'],1),
("Chemieunfall in Labor",'gsg',[2,3],{},[1,3,.5,'inn'],2),
("Säureaustritt",'gsg',[2,3],{},[0,2,.4,'bra'],2),
("Ammoniakaustritt",'gsg',[3,4],{},[1,4,.5,'inn'],1),
("Unfall in Chemiebetrieb",'gsg',[3,4],{},[1,4,.5,'inn'],1),
("Verdächtiger Gegenstand mit Pulver",'gsg',[2,3],{},[0,2,.2,'inn'],2),
("Radioaktiver Stoff",'gsg',[3,4],{},[0,2,.3,'inn'],1),
("Wasserrettung",'wasser',[1,2],{},[1,1,.6,'inn'],3),
("Person im Wasser",'wasser',[1,2,3],{},[1,1,.7,'inn'],3),
("Person im Eis eingebrochen",'wasser',[2,3],{},[1,1,.8,'inn'],2),
("Boot gekentert",'wasser',[2,3],{},[1,3,.5,'inn'],2),
("Boot in Seenot",'wasser',[1,2],{},[0,2,.3,'inn'],2),
("Schiff leckgeschlagen",'wasser',[2,3],{2:['RW']},[0,2,.2,'inn'],1),
("Ölfilm auf Gewässer",'wasser',[1,2],{1:['OEL']},[0,0,0,'inn'],3),
("Vermisste Person am Ufer",'wasser',[2],{},[0,1,.5,'inn'],2),
]
STUFE_MULT={}
def slug(s):
    s=unicodedata.normalize('NFKD',s.lower()).encode('ascii','ignore').decode()
    return re.sub(r'[^a-z0-9]+','_',s).strip('_')[:40]
out=[];ids=set()
for name,kind,levels,extra,pat,freq in S:
    for lvl in levels:
        req,m,w,f=base(kind,lvl)
        if kind=='klein': req,m,w,f=base('klein',1)
        for k,lst in extra.items():
            if lvl>=k:
                for g in lst:
                    ex=next((r for r in req if r['label']==G[g][1]),None)
                    if not ex: req.append(R(g))
        # Patienten je nach Stufe skalieren
        pmin,pmax,na,dept=pat
        if kind in('geb','frei','fzg','gsg') and pmax>0:
            sc=max(0,lvl-levels[0]); pmin=min(pmin+sc//2,pmax); pmax=pmax
        cat='b' if kind in('geb','frei','fzg') else 'th'
        stw=('BRAND %d'%lvl) if cat=='b' else ('TH %d'%(lvl if kind!='klein' else 0))
        short=('B%d'%lvl) if cat=='b' else ('TH%d'%(lvl if kind!='klein' else 0))
        if kind=='klein': stw='TH 0'; short='TH0'
        nveh=sum(r['count'] for r in req)
        mid=slug(name)+'_'+str(lvl); assert mid not in ids,mid; ids.add(mid)
        t={'id':mid,'code':stw,'short':short,'cat':cat,'name':name,'need':{'water':w,'foam':f},'minutes':m,
'weight':max(1,round(freq*{1:1,2:.8,3:.5,4:.3,5:.15,6:.08}[lvl if kind!='klein' else 1]*10)/10),
           'minVehicles':nveh,'req':req}
        if pmax>0: t['pat']=[pmin,pmax,na,dept]
        out.append(t)
print(len(out),'Einsätze aus',len(S),'Szenarien')
from collections import Counter
print(Counter(t['code'] for t in out))
import os
p=os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','index.html'); s=open(p,encoding='utf-8').read()
m=re.search(r'^const MISSION_TYPES = (\[.*\]);$',s,re.M)
s=s[:m.start(1)]+json.dumps(out,ensure_ascii=False)+s[m.end(1):]
open(p,'w',encoding='utf-8').write(s)
