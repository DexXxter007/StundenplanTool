import random
from collections import defaultdict
from constants import TAGE_DER_WOCHE

class Scheduler:
    def __init__(self, lehrerliste, klassenliste, angebote_liste, sammelangebote_liste, num_slots, stunden_pro_tag_config):
        self.lehrerliste = {l['name']: l for l in lehrerliste}
        self.klassenliste = {k['klasse']: k for k in klassenliste}
        self.angebote_liste = {a['name']: a for a in angebote_liste}
        self.sammelangebote_liste = sammelangebote_liste
        self.num_slots = num_slots
        self.stunden_pro_tag_config = stunden_pro_tag_config
        self.meldungen = []

        # Initialisiere den leeren Plan
        self.plan = {"A": {}, "B": {}}
        for woche in ["A", "B"]:
            for klasse_name in self.klassenliste:
                self.plan[woche][klasse_name] = {tag: [None] * self.num_slots for tag in TAGE_DER_WOCHE}

        # Initialisiere die Auslastungstracker
        self.lehrer_auslastung_woche = {"A": defaultdict(int), "B": defaultdict(int)}
        self.klasse_auslastung_tag = {"A": defaultdict(lambda: defaultdict(int)), "B": defaultdict(lambda: defaultdict(int))}
        self.lehrer_auslastung_tag = {"A": defaultdict(lambda: defaultdict(int)), "B": defaultdict(lambda: defaultdict(int))}
        self.platzierte_doppelbloecke = {"A": defaultdict(lambda: defaultdict(set)), "B": defaultdict(lambda: defaultdict(set))}

        self.max_backtracking_runs = 50  # Maximale Anzahl an Backtracking-Versuchen
        self.best_plan = None
        self.best_score = float('-inf')

    def generate_schedule(self):
        """Hauptmethode zur Erstellung des Stundenplans."""
        max_runs = 100
        best_plan = None
        best_score = float('-inf')

        for run in range(max_runs):
            self._reset_plan()
            self._platziere_sammelangebote()
            
            # Sammle ALLE Anforderungen von ALLEN Klassen
            stunden_anforderungen = self._sammle_stunden_anforderungen()

            # Anforderungen sortieren: Teilungsstunden und Hauptangebote zuerst, dann Rest
            teilung_anforderungen = []
            hauptangebot_anforderungen = []
            rest_anforderungen = []

            for req in stunden_anforderungen:
                # Teilungsstunden: Wenn angebote_stunden für diese Klasse/Angebot stunden_teilung > 0
                ist_teilung = False
                klasse_info = self.klassenliste.get(req['klasse'], {})
                for angebot_def in klasse_info.get("angebote_stunden", []):
                    if angebot_def.get("angebot") == req["angebot"] and angebot_def.get("stunden_teilung", 0) > 0:
                        ist_teilung = True
                        break
                if ist_teilung:
                    teilung_anforderungen.append(req)
                    continue

                # Hauptangebot: Wenn mind. ein Lehrer dieses Angebot als hauptangebot=True hat
                ist_haupt = False
                for l_info in self.lehrerliste.values():
                    for angebot in l_info.get('angebote', []):
                        if angebot.get('angebot') == req['angebot'] and angebot.get('hauptangebot', True):
                            ist_haupt = True
                            break
                    if ist_haupt:
                        break
                if ist_haupt:
                    hauptangebot_anforderungen.append(req)
                    continue

                # Rest
                rest_anforderungen.append(req)

            # Reihenfolge: Teilung → Hauptangebot → Rest
            sortierte_anforderungen = teilung_anforderungen + hauptangebot_anforderungen + rest_anforderungen

            # Iteriere durch die sortierten Anforderungen und platziere sie "gierig"
            for req in sortierte_anforderungen:
                moegliche_platzierungen = self._finde_alle_moeglichen_platzierungen_fuer_req(req)

                # Platzierung: Hauptfach-Lehrer und Teilungslehrer bevorzugen
                if moegliche_platzierungen:
                    def platzierung_sort_key(platz):
                        lehrer_name = platz['lehrer']
                        l_info = self.lehrerliste[lehrer_name]
                        # Hauptangebot?
                        ist_haupt = any(
                            a.get('angebot') == req['angebot'] and a.get('hauptangebot', True)
                            for a in l_info.get('angebote', [])
                        )
                        # Teilungslehrer? (wenn in angebote_stunden ein lehrer1_name/lehrer2_name steht)
                        teilungs_bonus = 0
                        klasse_info = self.klassenliste.get(req['klasse'], {})
                        for angebot_def in klasse_info.get("angebote_stunden", []):
                            if angebot_def.get("angebot") == req["angebot"]:
                                if lehrer_name in (angebot_def.get("lehrer1_name"), angebot_def.get("lehrer2_name")):
                                    teilungs_bonus = 1
                        return (-ist_haupt, -teilungs_bonus)
                    moegliche_platzierungen.sort(key=platzierung_sort_key)

                    platzierung = moegliche_platzierungen[0]
                    lehrer_name = platzierung['lehrer']
                    tag = platzierung['tag']
                    slot = platzierung['slot']
                    dauer = req['dauer']
                    woche = req['woche']
                    klasse_name = req['klasse']
                    angebot_name = req['angebot']

                    for i in range(dauer):
                        self.plan[woche][klasse_name][tag][slot + i] = {"angebot": angebot_name, "lehrer": lehrer_name}
                    self.lehrer_auslastung_woche[woche][lehrer_name] += dauer
                    self.lehrer_auslastung_tag[woche][lehrer_name][tag] += dauer
                else:
                    self.meldungen.append(f"WARNUNG (Run {run+1}): Keine Platzierung für {req['angebot']} in {req['klasse']} (Woche {req['woche']}) gefunden.")

            # Bewertung des Gesamtplans dieses Durchlaufs
            score = self._bewerte_plan()
            if score > best_score:
                import copy
                best_plan = copy.deepcopy(self.plan)
                best_score = score

        # --- Vermeide zu große Session-Daten: Nur die wichtigsten Meldungen speichern ---
        if best_plan:
            self.plan = best_plan
            # Nur die letzten 30 Meldungen speichern, um Cookie-Overflow zu vermeiden
            self.meldungen = self.meldungen[-30:]
            self.meldungen.append(f"INFO: Planerstellung abgeschlossen (beste Variante von {max_runs} Runs, Score={best_score}).")
        else:
            self.meldungen = self.meldungen[-30:]
            self.meldungen.append("FEHLER: Es konnte kein gültiger Stundenplan erstellt werden.")

        return self.plan, self.meldungen


    def _reset_plan(self):
        # Setze Plan und Tracker zurück
        self.plan = {"A": {}, "B": {}}
        for woche in ["A", "B"]:
            for klasse_name in self.klassenliste:
                self.plan[woche][klasse_name] = {tag: [None] * self.num_slots for tag in TAGE_DER_WOCHE}
        self.lehrer_auslastung_woche = {"A": defaultdict(int), "B": defaultdict(int)}
        self.klasse_auslastung_tag = {"A": defaultdict(lambda: defaultdict(int)), "B": defaultdict(lambda: defaultdict(int))}
        self.lehrer_auslastung_tag = {"A": defaultdict(lambda: defaultdict(int)), "B": defaultdict(lambda: defaultdict(int))}


    def _bewerte_plan(self):
        # Einfache Bewertungsfunktion: Zähle belegte Stunden (je mehr, desto besser)
        score = 0
        for woche in self.plan:
            for klasse in self.plan[woche]:
                for tag in self.plan[woche][klasse]:
                    for eintrag in self.plan[woche][klasse][tag]:
                        if eintrag is not None:
                            score += 1
        return score

    def _platziere_sammelangebote(self):
        # Diese Funktion muss idempotent sein, d.h. sie sollte den Zustand korrekt setzen
        for sa in self.sammelangebote_liste:
            woche_typ = sa.get("woche_typ", "AB")
            wochen = ["A", "B"] if woche_typ == "AB" else [woche_typ]
            dauer = sa.get("dauer_stunden", 2)
            lehrer_namen = sa.get("lehrer_namen", [])
            kernangebot = sa.get("kernangebot")
            klassen_namen = sa.get("teilnehmende_klassen_namen", [])

            for woche in wochen:
                # Finde einen passenden Slot für alle Klassen und Lehrer gleichzeitig
                passender_slot_gefunden = False
                for tag in TAGE_DER_WOCHE:
                    # Für Doppelstunden nur gerade Startslots prüfen
                    start_slots = range(self.num_slots - dauer + 1)
                    if dauer == 2:
                        start_slots = [s for s in start_slots if s % 2 == 0]

                    for slot in start_slots:
                        ist_frei = True
                        # Prüfe alle Klassen
                        for klasse in klassen_namen:
                            for i in range(dauer):
                                if self.plan[woche][klasse][tag][slot + i] is not None:
                                    ist_frei = False
                                    break
                            if not ist_frei: break
                        if not ist_frei: continue

                        # Prüfe alle Lehrer
                        for lehrer in lehrer_namen:
                            # Wochenstunden
                            if self.lehrer_auslastung_woche[woche].get(lehrer, 0) + dauer > self.lehrerliste[lehrer].get(f"stunden_{woche.lower()}", 0):
                                ist_frei = False
                                break
                            # Tagesstunden & Doppelbelegung
                            for i in range(dauer):
                                if self.lehrer_auslastung_tag[woche][lehrer].get(tag, 0) + dauer > self.lehrerliste[lehrer].get("max_stunden_pro_tag", {}).get(tag, {}).get(woche, self.num_slots):
                                    ist_frei = False
                                    break
                                # Prüfe Doppelbelegung in *jeder* Klasse
                                for k_name in self.klassenliste:
                                    if self.plan[woche][k_name][tag][slot + i] and self.plan[woche][k_name][tag][slot + i].get('lehrer') == lehrer:
                                        ist_frei = False
                                        break
                                if not ist_frei: break
                            if not ist_frei: break
                        if not ist_frei: continue

                        # Wenn alles frei ist, platziere den Block
                        if ist_frei:
                            for klasse in klassen_namen:
                                for i in range(dauer):
                                    self.plan[woche][klasse][tag][slot + i] = {
                                        "angebot": kernangebot,
                                        "lehrer": lehrer_namen[0],
                                        "lehrer2": lehrer_namen[1] if len(lehrer_namen) > 1 else None,
                                        "sammelangebot": True
                                    }
                            for lehrer in lehrer_namen:
                                self.lehrer_auslastung_woche[woche][lehrer] += dauer
                                self.lehrer_auslastung_tag[woche][lehrer][tag] += dauer
                            self.meldungen.append(f"INFO: Sammelangebot '{sa.get('name')}' in Woche {woche}, Tag {tag}, Slot {slot+1}-{slot+dauer} platziert.")
                            passender_slot_gefunden = True
                            break # Nächster Tag
                    if passender_slot_gefunden:
                        break # Nächste Woche
                if not passender_slot_gefunden:
                    self.meldungen.append(f"FEHLER: Sammelangebot '{sa.get('name')}' konnte in Woche {woche} nicht platziert werden.")


    def _sammle_stunden_anforderungen(self):
        anforderungen = []
        for klasse_name, klasse_info in self.klassenliste.items():
            wochen_typ_klasse = klasse_info.get("woche", "AB")
            for angebot_def in klasse_info.get("angebote_stunden", []):
                angebot_name = angebot_def.get("angebot")
                stunden_gesamt = angebot_def.get("stunden_gesamt", 0)
                if not angebot_name or stunden_gesamt == 0:
                    continue
                angebot_info = self.angebote_liste.get(angebot_name, {})
                block_groesse = angebot_info.get("block_groesse", 2)
                num_doppel = stunden_gesamt // 2 if block_groesse == 2 else 0
                num_einzel = stunden_gesamt % 2 if block_groesse == 2 else stunden_gesamt
                wochen_liste = ["A", "B"] if wochen_typ_klasse == "AB" else [wochen_typ_klasse]
                for woche in wochen_liste:
                    for _ in range(num_doppel):
                        anforderungen.append({"woche": woche, "klasse": klasse_name, "angebot": angebot_name, "dauer": 2})
                    for _ in range(num_einzel):
                        anforderungen.append({"woche": woche, "klasse": klasse_name, "angebot": angebot_name, "dauer": 1})
        anforderungen.sort(key=lambda x: x['dauer'], reverse=True)
        return anforderungen

    def _finde_alle_moeglichen_platzierungen_fuer_req(self, req):
        platzierungen = []
        woche, klasse_name, angebot_name, dauer = req['woche'], req['klasse'], req['angebot'], req['dauer']
        klasse_info = self.klassenliste[klasse_name]
        angebot_info = self.angebote_liste.get(angebot_name, {})
        block_groesse = angebot_info.get("block_groesse", 2)
        nur_ein_doppelblock_pro_tag = angebot_info.get("nur_ein_doppelblock_pro_tag", False)
        
        # PATCH: Hole die ID der Klasse, falls vorhanden (für Einsatzklassen-Filter)
        klasse_id = klasse_info.get("id", None)
        # NEU: Nur Lehrer zulassen, die in dieser Klasse eingesetzt werden dürfen (oder alle, falls Liste leer)
        lehrer_kandidaten = []
        for name, l_info in self.lehrerliste.items():
            einsatz_klassen = l_info.get("einsatz_klassen", [])
            # PATCH: Robust für JSON-String oder Liste
            if isinstance(einsatz_klassen, str):
                try:
                    einsatz_klassen = json.loads(einsatz_klassen)
                except Exception:
                    einsatz_klassen = []
            # Wenn keine Einschränkung, dann alle Klassen erlaubt
            if not einsatz_klassen or (klasse_id is not None and klasse_id in einsatz_klassen) or klasse_name in einsatz_klassen:
                if any(a.get('angebot') == angebot_name for a in l_info.get('angebote', [])):
                    lehrer_kandidaten.append(name)
        random.shuffle(lehrer_kandidaten)

        for lehrer_name in lehrer_kandidaten:
            lehrer_info = self.lehrerliste[lehrer_name]

            # --- KORREKTUR: Die folgende Logik muss für JEDEN Kandidaten laufen, nicht nur für Hauptfachlehrer. ---
            # Die Bevorzugung von Hauptfachlehrern geschieht bereits beim Erstellen der `anforderungen`.

            # --- WICHTIG: Lehrer muss überhaupt Stunden haben! ---
            stunden_woche = None
            if f'stunden_{woche.lower()}' in lehrer_info:
                stunden_woche = lehrer_info.get(f'stunden_{woche.lower()}')
            elif f'stunden_{woche.upper()}' in lehrer_info:
                stunden_woche = lehrer_info.get(f'stunden_{woche.upper()}')
            elif woche == "A":
                stunden_woche = lehrer_info.get("stunden_a", lehrer_info.get("stunden_A", 0))
            elif woche == "B":
                stunden_woche = lehrer_info.get("stunden_b", lehrer_info.get("stunden_B", 0))
            if stunden_woche is None or stunden_woche <= 0:
                continue

            # Wochenstunden-Check
            if self.lehrer_auslastung_woche[woche].get(lehrer_name, 0) + dauer > stunden_woche:
                continue

            arbeitstage_klasse = set(klasse_info.get("arbeitstage", TAGE_DER_WOCHE))
            arbeitstage_lehrer = set(lehrer_info.get("tage", TAGE_DER_WOCHE))
            abwesend_lehrer = set(lehrer_info.get("abwesend_an_tagen", []))
            moegliche_tage = list(arbeitstage_klasse.intersection(arbeitstage_lehrer) - abwesend_lehrer)
            random.shuffle(moegliche_tage)

            for tag in moegliche_tage:
                # --- Blockplatzierung: Nur auf passenden Slots ---
                start_slots = range(self.num_slots - dauer + 1)
                if block_groesse == 2:
                    start_slots = [s for s in start_slots if s % 2 == 0]

                # --- Nur ein Doppelblock pro Tag für dieses Angebot ---
                if nur_ein_doppelblock_pro_tag and dauer == 2:
                    doppelblock_vorhanden = any(
                        self.plan[woche][klasse_name][tag][slot] and
                        self.plan[woche][klasse_name][tag][slot].get("angebot") == angebot_name and
                        slot % 2 == 0 and
                        slot + 1 < self.num_slots and
                        self.plan[woche][klasse_name][tag][slot + 1] and
                        self.plan[woche][klasse_name][tag][slot + 1].get("angebot") == angebot_name
                        for slot in start_slots
                    )
                    if doppelblock_vorhanden:
                        continue

                # --- Lehrer darf pro Tag in dieser Klasse nur einmal vorkommen ---
                lehrer_bereits_an_tag_gebucht = any(
                    slot_eintrag and slot_eintrag.get('lehrer') == lehrer_name
                    for slot_eintrag in self.plan[woche][klasse_name][tag]
                )
                if lehrer_bereits_an_tag_gebucht:
                    continue

                # Tagesstunden-Check
                max_std_tag_lehrer = lehrer_info.get("max_stunden_pro_tag", {}).get(tag, {}).get(woche, self.num_slots)
                if self.lehrer_auslastung_tag[woche][lehrer_name].get(tag, 0) + dauer > max_std_tag_lehrer:
                    continue

                # --- Klasse: Maximalbelegung pro Tag ---
                max_stunden_klasse = klasse_info.get("max_stunden_klasse", self.num_slots)
                belegte_stunden_klasse = sum(1 for x in self.plan[woche][klasse_name][tag] if x is not None)
                if belegte_stunden_klasse + dauer > max_stunden_klasse:
                    continue

                for slot in start_slots:
                    konflikt = False
                    for i in range(dauer):
                        pruef_slot = slot + i
                        # 1. Ist die Klasse selbst an dieser Stelle frei?
                        if self.plan[woche][klasse_name][tag][pruef_slot] is not None:
                            konflikt = True
                            break
                        # 2. Ist der Lehrer in einer ANDEREN Klasse zu dieser Zeit belegt?
                        for andere_klasse in self.klassenliste:
                            if andere_klasse == klasse_name:
                                continue
                            eintrag = self.plan[woche][andere_klasse][tag][pruef_slot]
                            if eintrag and eintrag.get('lehrer') == lehrer_name:
                                konflikt = True
                                break
                        if konflikt:
                            break
                    if not konflikt:
                        platzierungen.append({"lehrer": lehrer_name, "tag": tag, "slot": slot})

        # Wenn KEINE Platzierung möglich ist, logge eine Meldung für Debugging
        if not platzierungen:
            self.meldungen.append(
                f"WARNUNG: Keine Platzierung möglich für {angebot_name} ({dauer}) in {klasse_name} Woche {woche} (Lehrer: {lehrer_kandidaten})"
            )
        return platzierungen


def generate_schedule_data(
    lehrerliste, klassenliste, angebote_liste, sammelangebote_liste,
    klassen_namen_im_plan_display_order, num_slots_pro_tag, stunden_pro_tag_config
):
    scheduler = Scheduler(
        lehrerliste, klassenliste, angebote_liste, sammelangebote_liste,
        num_slots_pro_tag, stunden_pro_tag_config
    )
    return scheduler.generate_schedule()

# Hinweis für Fortschrittsanzeige im Frontend:
# Die Fortschrittsanzeige im Backend (print) ist nur im Terminal sichtbar.
# Für ein echtes Fortschritts-Popup im Frontend müsste die Planerstellung asynchron (z.B. mit Celery oder WebSockets)
# und mit AJAX/JavaScript im Browser umgesetzt werden. Das ist mit Flask allein nicht "live" möglich.
# Du kannst aber die Meldungen (self.meldungen) nach der Planerstellung als Popup im Frontend anzeigen.
# Du kannst aber die Meldungen (self.meldungen) nach der Planerstellung als Popup im Frontend anzeigen.
# Du kannst aber die Meldungen (self.meldungen) nach der Planerstellung als Popup im Frontend anzeigen.
