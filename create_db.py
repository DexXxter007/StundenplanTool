import os
from app import app, db

# Dieses Skript's einzige Aufgabe ist es, die Datenbank-Struktur sauber zu erstellen.

def create_database():
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    if not os.path.isabs(db_path):
        db_path = os.path.join(os.getcwd(), db_path)

    print("--- Datenbank Erstellungs-Skript ---")
    print(f"Zieldatenbank: {db_path}")

    if os.path.exists(db_path):
        print("Lösche alte Datenbank...")
        os.remove(db_path)
        print("Alte Datenbank gelöscht.")

    with app.app_context():
        print("Erstelle alle Tabellen basierend auf den aktuellen Modellen...")
        db.create_all()
        print("Tabellen erfolgreich erstellt.")

if __name__ == '__main__':
    create_database()

