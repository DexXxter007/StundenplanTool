import json
from app import app, db
from models import Lehrer, Angebot, Klasse, User

def migrate_angebote(lehrer_data, klassen_data):
    """Sammelt alle Angebote aus den JSON-Dateien und erstellt sie, falls sie nicht existieren."""
    print("Starte Angebotsmigration...")
    angebot_namen = set()

    # Angebote aus lehrer.json sammeln
    for lehrer in lehrer_data:
        for angebot in lehrer.get('angebote', []):
            angebot_namen.add(angebot.get('angebot'))

    # Angebote aus klassen.json sammeln
    for klasse in klassen_data:
        for angebot_def in klasse.get('angebote_stunden', []):
            angebot_namen.add(angebot_def.get('angebot'))

    # Leere Namen entfernen
    angebot_namen.discard(None)

    # Angebote in der DB erstellen
    count = 0
    for name in angebot_namen:
        if not Angebot.query.filter_by(name=name).first():
            neues_angebot = Angebot(name=name)
            db.session.add(neues_angebot)
            count += 1
    db.session.commit()
    print(f"{count} neue Angebote erstellt.")

def migrate_lehrer(lehrer_data):
    """Liest lehrer.json und migriert die Daten in die Datenbank."""
    print("Starte Lehrermigration...")
    for lehrer_eintrag in lehrer_data:
        name = lehrer_eintrag.get('name')
        if not name or Lehrer.query.filter_by(name=name).first():
            print(f"Überspringe Lehrer '{name}', da er bereits existiert oder keinen Namen hat.")
            continue

        neuer_lehrer = Lehrer(
            name=name,
            stunden_gesamt_soll_input=str(lehrer_eintrag.get('stunden_gesamt_soll_input', '')),
            stunden_a_input=str(lehrer_eintrag.get('stunden_a_input', '')),
            stunden_b_input=str(lehrer_eintrag.get('stunden_b_input', '')),
            stunden_a=lehrer_eintrag.get('stunden_a', 0),
            stunden_b=lehrer_eintrag.get('stunden_b', 0),
            farbe=lehrer_eintrag.get('farbe', '#808080'),
            tage=lehrer_eintrag.get('tage', []),
            # Korrigierte Speicherung von max_stunden_pro_tag als JSON-Objekt
            max_stunden_pro_tag={
                "Mo": {"A": lehrer_eintrag.get('max_stunden_pro_tag', {}).get('Mo', {}).get('A', 8), "B": lehrer_eintrag.get('max_stunden_pro_tag', {}).get('Mo', {}).get('B', 8)},
                "Di": {"A": lehrer_eintrag.get('max_stunden_pro_tag', {}).get('Di', {}).get('A', 8), "B": lehrer_eintrag.get('max_stunden_pro_tag', {}).get('Di', {}).get('B', 8)},
                "Mi": {"A": lehrer_eintrag.get('max_stunden_pro_tag', {}).get('Mi', {}).get('A', 8), "B": lehrer_eintrag.get('max_stunden_pro_tag', {}).get('Mi', {}).get('B', 8)},
                "Do": {"A": lehrer_eintrag.get('max_stunden_pro_tag', {}).get('Do', {}).get('A', 8), "B": lehrer_eintrag.get('max_stunden_pro_tag', {}).get('Do', {}).get('B', 8)},
                "Fr": {"A": lehrer_eintrag.get('max_stunden_pro_tag', {}).get('Fr', {}).get('A', 8), "B": lehrer_eintrag.get('max_stunden_pro_tag', {}).get('Fr', {}).get('B', 8)}
            },
            abwesend_an_tagen=lehrer_eintrag.get('abwesend_an_tagen', [])
        )
        db.session.add(neuer_lehrer) # Füge den Lehrer zur Session hinzu, BEVOR Beziehungen geändert werden

        # Verknüpfe Angebote und setze das Hauptangebot
        hauptangebot_gefunden = False
        for angebot_def in lehrer_eintrag.get('angebote', []):
            angebot_name = angebot_def.get('angebot')
            angebot_obj = Angebot.query.filter_by(name=angebot_name).first()
            if angebot_obj:
                neuer_lehrer.angebote.append(angebot_obj)
                if angebot_def.get('hauptangebot') and not hauptangebot_gefunden:
                    neuer_lehrer.hauptangebot_id = angebot_obj.id
                    hauptangebot_gefunden = True
    db.session.commit()
    print(f"{len(lehrer_data)} Lehrer verarbeitet.")

def migrate_klassen(klassen_data):
    """Liest klassen.json und migriert die Daten in die Datenbank."""
    print("Starte Klassenmigration...")
    for klasse_eintrag in klassen_data:
        name = klasse_eintrag.get('klasse')
        if not name or Klasse.query.filter_by(name=name).first():
            print(f"Überspringe Klasse '{name}', da sie bereits existiert oder keinen Namen hat.")
            continue

        neue_klasse = Klasse(
            name=name,
            max_stunden_klasse=klasse_eintrag.get('max_stunden_klasse', 6),
            woche=klasse_eintrag.get('woche', 'AB'),
            arbeitstage=klasse_eintrag.get('arbeitstage', ["Mo", "Di", "Mi", "Do", "Fr"]),
            angebote_stunden=klasse_eintrag.get('angebote_stunden', [])
        )
        db.session.add(neue_klasse)
    db.session.commit()
    print(f"{len(klassen_data)} Klassen verarbeitet.")

if __name__ == '__main__':
    with app.app_context():
        print("--- Datenmigrations-Skript ---")
        print("Annahme: Datenbank und Tabellen existieren bereits.")

        # Lade JSON-Daten
        try:
            with open('lehrer.json', 'r', encoding='utf-8') as f:
                lehrer_data = json.load(f)
            with open('klassen.json', 'r', encoding='utf-8') as f:
                klassen_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Fehler beim Laden der JSON-Dateien: {e}")
            exit(1) # Beendet das Skript bei einem Fehler

        migrate_angebote(lehrer_data, klassen_data)
        migrate_lehrer(lehrer_data)
        migrate_klassen(klassen_data)
        print("Migration abgeschlossen.")
