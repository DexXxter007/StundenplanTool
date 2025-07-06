from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, Table, Text
from sqlalchemy.orm import relationship
from sqlalchemy.types import PickleType

# Initialisiere die SQLAlchemy-Instanz.
# Diese wird in app.py mit der Flask-App verbunden.
db = SQLAlchemy()

# =====================================================================
# Authentifizierung
# =====================================================================

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False) # Used for login
    email = db.Column(db.String(120), unique=True, nullable=False) # Keep email for contact/recovery
    # Das Passwort wird als Hash gespeichert, nicht als Klartext (60 Zeichen für Bcrypt).
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), default='Benutzer', nullable=False) # New role column
    farbe = db.Column(db.String(7), default='#808080') # Hex color

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

# =====================================================================
# Kerndatenmodelle (Lehrer, Angebote, Klassen etc.)
# =====================================================================

# Association table for Lehrer <-> Angebot
lehrer_angebot_association = db.Table('lehrer_angebot_association',
    db.Column('lehrer_id', db.Integer, db.ForeignKey('lehrer.id'), primary_key=True),
    db.Column('angebot_id', db.Integer, db.ForeignKey('angebot.id'), primary_key=True)
)

# Association table for Sammelangebot <-> Klasse
sammelangebot_klasse_association = db.Table('sammelangebot_klasse_association',
    db.Column('sammelangebot_id', db.Integer, db.ForeignKey('sammelangebot.id'), primary_key=True),
    db.Column('klasse_id', db.Integer, db.ForeignKey('klasse.id'), primary_key=True)
)

class Lehrer(db.Model):
    __tablename__ = 'lehrer'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    stunden_gesamt_soll_input = db.Column(db.String(10), default='26')
    stunden_a_input = db.Column(db.String(10), default='')
    stunden_b_input = db.Column(db.String(10), default='')
    stunden_a = db.Column(db.Integer, default=0)
    stunden_b = db.Column(db.Integer, default=0)
    farbe = db.Column(db.String(7), default='#808080') # Hex color
    tage = db.Column(db.JSON, default=lambda: ["Mo", "Di", "Mi", "Do", "Fr"])
    max_stunden_pro_tag = db.Column(db.JSON, default=lambda: {}) # Speichert {Tag: {WocheA: X, WocheB: Y}}
    abwesend_an_tagen = db.Column(db.JSON, default=list)
    angebote = db.relationship('Angebot', secondary=lehrer_angebot_association, backref='lehrer')

    # --- NEU: Beziehung zum Hauptangebot ---
    # Wir brauchen eine explizite Fremdschlüsselbeziehung für das Hauptangebot.
    hauptangebot_id = db.Column(db.Integer, db.ForeignKey('angebot.id'), nullable=True)
    # 'foreign_keys' ist notwendig, da es bereits eine Beziehung zu 'Angebot' gibt (many-to-many).
    hauptangebot = db.relationship('Angebot', foreign_keys=[hauptangebot_id])

    einsatz_klassen = db.Column(db.Text, default="[]")  # PATCH: als JSON-String speichern, falls kein PickleType/JSON verfügbar

    # Falls du SQLAlchemy >=1.3 und SQLite >=3.9 nutzt, kannst du auch:
    # einsatz_klassen = db.Column(db.JSON, default=list)
    # oder für PickleType:
    # einsatz_klassen = db.Column(PickleType, default=list)

    def __repr__(self):
        return f'<Lehrer {self.name}>'

class Angebot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    block_groesse = db.Column(db.Integer, default=2, nullable=False) # 1 für Einzelstunde, 2 für Doppelstunde
    nur_ein_doppelblock_pro_tag = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return f'<Angebot {self.name}>'

class Klasse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    max_stunden_klasse = db.Column(db.Integer, default=6)
    woche = db.Column(db.String(2), default='AB') # A, B, AB
    arbeitstage = db.Column(db.JSON, default=lambda: ["Mo", "Di", "Mi", "Do", "Fr"])
    # Wir speichern die Angebotsdefinitionen als JSON, um die Struktur einfach zu halten.
    angebote_stunden = db.Column(db.JSON, default=list)

    def __repr__(self):
        return f'<Klasse {self.name}>'

class Sammelangebot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    dauer_stunden = db.Column(db.Integer, default=2)
    woche_typ = db.Column(db.String(2), default='A') # A, B, AB

    kernangebot_id = db.Column(db.Integer, db.ForeignKey('angebot.id'), nullable=False)
    kernangebot = db.relationship('Angebot')

    lehrer_id = db.Column(db.Integer, db.ForeignKey('lehrer.id'), nullable=False)
    lehrer = db.relationship('Lehrer')

    teilnehmende_klassen = db.relationship('Klasse', secondary=sammelangebot_klasse_association, backref='sammelangebote')

    def __repr__(self):
        return f'<Sammelangebot {self.name}>'

class StundenplanEintrag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    woche = db.Column(db.String(1), nullable=False)
    tag = db.Column(db.String(2), nullable=False)
    slot = db.Column(db.Integer, nullable=False)
    klasse_id = db.Column(db.Integer, db.ForeignKey('klasse.id'), nullable=False)
    klasse = db.relationship('Klasse', backref='stundenplan_eintraege')
    angebot_id = db.Column(db.Integer, db.ForeignKey('angebot.id'), nullable=False)
    angebot = db.relationship('Angebot')
    lehrer1_id = db.Column(db.Integer, db.ForeignKey('lehrer.id'), nullable=False)
    lehrer1 = db.relationship('Lehrer', foreign_keys=[lehrer1_id])
    lehrer2_id = db.Column(db.Integer, db.ForeignKey('lehrer.id'), nullable=True)
    lehrer2 = db.relationship('Lehrer', foreign_keys=[lehrer2_id])

    __table_args__ = (db.UniqueConstraint('woche', 'tag', 'slot', 'klasse_id', name='_woche_tag_slot_klasse_uc'),)

# =====================================================================
# App-Einstellungen
# =====================================================================
class Einstellung(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)

# =====================================================================
# Kalender-Events
# =====================================================================
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    start = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end = db.Column(db.DateTime, nullable=True)
    all_day = db.Column(db.Boolean, default=False, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('events', lazy=True))
    # NEU: Status für die Genehmigung
    status = db.Column(db.String(20), default='pending', nullable=False) # Werte: 'pending', 'approved', 'rejected'

    def __repr__(self):
        return f"Event('{self.title}', '{self.start}', '{self.status}')"

# =====================================================================
# Kanban-Board
# =====================================================================

class KanbanList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    position = db.Column(db.Integer, nullable=False)
    # Wenn eine Liste gelöscht wird, werden alle zugehörigen Karten mitgelöscht.
    cards = db.relationship('KanbanCard', backref='list', lazy=True, cascade="all, delete-orphan", order_by="KanbanCard.position")

    def __repr__(self):
        return f"KanbanList('{self.name}', '{self.position}')"

class KanbanCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    position = db.Column(db.Integer, nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey('kanban_list.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Verknüpfung zum Benutzer, der die Karte erstellt hat
    creator = db.relationship('User')

    def __repr__(self):
        return f"KanbanCard('{self.content}', '{self.position}')"

# =====================================================================
# Vertretungsplan
# =====================================================================

class Vertretungsplan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gueltig_von = db.Column(db.Date, nullable=False)
    gueltig_bis = db.Column(db.Date, nullable=False)
    vorlage_woche = db.Column(db.String(1), nullable=False) # NEU: Speichert 'A' oder 'B'
    erstellt_am = db.Column(db.DateTime, default=datetime.utcnow)
    # Dies sorgt dafür, dass beim Löschen eines Plans auch alle zugehörigen Einträge gelöscht werden.
    eintraege = db.relationship('VertretungsplanEintrag', backref='vertretungsplan', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Vertretungsplan von {self.gueltig_von.strftime("%d.%m")} bis {self.gueltig_bis.strftime("%d.%m")}>'

class VertretungsplanEintrag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vertretungsplan_id = db.Column(db.Integer, db.ForeignKey('vertretungsplan.id'), nullable=False)
    
    # Dies sind die kopierten Felder aus dem Hauptstundenplan
    tag = db.Column(db.String(20), nullable=False)
    slot = db.Column(db.Integer, nullable=False)
    klasse_id = db.Column(db.Integer, db.ForeignKey('klasse.id'), nullable=False)
    angebot_id = db.Column(db.Integer, db.ForeignKey('angebot.id'), nullable=False)
    lehrer1_id = db.Column(db.Integer, db.ForeignKey('lehrer.id'), nullable=False)
    lehrer2_id = db.Column(db.Integer, db.ForeignKey('lehrer.id'), nullable=True)

    # Beziehungen, um auf die verknüpften Objekte zugreifen zu können
    klasse = db.relationship('Klasse')
    angebot = db.relationship('Angebot')
    lehrer1 = db.relationship('Lehrer', foreign_keys=[lehrer1_id])
    lehrer2 = db.relationship('Lehrer', foreign_keys=[lehrer2_id])

    def __repr__(self):
        return f'<VertretungsplanEintrag für Plan {self.vertretungsplan_id}>'
