from app import app, db
from models import KanbanList

def create_default_lists():
    """Checks if Kanban lists exist and creates default ones if not."""
    with app.app_context():
        # Check if any lists already exist
        if KanbanList.query.first():
            print("Kanban-Listen existieren bereits. Überspringe die Erstellung.")
            return

        print("Erstelle Standard-Kanban-Listen...")

        # Define default lists
        default_lists = [
            {"name": "Zu erledigen", "position": 0},
            {"name": "In Arbeit", "position": 1},
            {"name": "Erledigt", "position": 2}
        ]

        for list_data in default_lists:
            new_list = KanbanList(name=list_data["name"], position=list_data["position"])
            db.session.add(new_list)
        
        db.session.commit()
        print("Standard-Kanban-Listen erfolgreich erstellt.")

if __name__ == '__main__':
    create_default_lists()