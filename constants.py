# c:\Users\claud\Desktop\StundenplanWebApp\constants.py

# Tage der Woche für die Anzeige und Logik
TAGE_DER_WOCHE = ["Mo", "Di", "Mi", "Do", "Fr"]

# Farbpalette für die Lehrer zur visuellen Unterscheidung im Stundenplan.
# Der Schlüssel ist der Name, der im Frontend (z.B. in einem Dropdown) angezeigt wird,
# der Wert ist der Hex-Farbcode, der in der Datenbank gespeichert wird.
# Erweiterte Farbpalette für Lehrer
LEHRER_FARBEN_MAP = {
    'Pastellrot': '#ffadad',
    'Pastellorange': '#ffd6a5',
    'Pastellgelb': '#fdffb6',
    'Pastellgrün': '#caffbf',
    'Himmelblau': '#9bf6ff',
    'Pastellblau': '#a0c4ff',
    'Lavendel': '#bdb2ff',
    'Pastellrosa': '#ffc6ff',
    'Mintgrün': '#99e2b4',
    'Lachs': '#ff9d87',
    'Kornblume': '#83a6ed',
    'Salbei': '#b2d8b2',
    'Gold': '#fddd81',
    'Koralle': '#ffb39c',
    'Grau': '#d4d4d4',
    'Dunkelgrau': '#808080'
}

# Der Name der Standardfarbe aus der obigen Map, falls keine ausgewählt wird.
DEFAULT_LEHRER_FARBE_NAME = 'Grau'