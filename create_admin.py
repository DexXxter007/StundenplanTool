from app import app, db, bcrypt, ROLE_ADMIN
from models import User
from getpass import getpass

def create_admin():
    """Erstellt einen neuen Admin-Benutzer in der Datenbank."""
    with app.app_context():
        print("--- Admin-Benutzer erstellen ---")

        # Benutzernamen abfragen
        username = input("Geben Sie den Benutzernamen für den Admin ein: ").strip()
        if not username:
            print("Benutzername darf nicht leer sein.")
            return

        # Prüfen, ob der Benutzer bereits existiert
        if User.query.filter_by(username=username).first():
            print(f"Benutzer '{username}' existiert bereits.")
            return

        # E-Mail abfragen
        email = input(f"Geben Sie die E-Mail für '{username}' ein: ").strip()
        if not email:
            print("E-Mail darf nicht leer sein.")
            return

        # Passwort sicher abfragen
        password = getpass("Geben Sie das Passwort für den Admin ein: ")
        if not password:
            print("Passwort darf nicht leer sein.")
            return

        confirm_password = getpass("Bestätigen Sie das Passwort: ")
        if password != confirm_password:
            print("Passwörter stimmen nicht überein.")
            return

        # Passwort hashen und Benutzer erstellen
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        admin_user = User(
            username=username,
            email=email,
            password=hashed_password,
            role=ROLE_ADMIN  # Wichtig: Rolle auf Admin setzen
        )

        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin-Benutzer '{username}' erfolgreich erstellt!")

if __name__ == '__main__':
    create_admin()
