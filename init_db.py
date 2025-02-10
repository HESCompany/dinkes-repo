from flask_migrate import init, migrate, upgrade
from app import create_app, db
from app.models import User, File

app = create_app()

def init_database():
    with app.app_context():
        # Initialize migrations
        init()
        
        # Create a migration
        migrate(message="Initial migration")
        
        # Apply the migration
        upgrade()

        # Create tables
        db.create_all()

        print("Database initialized successfully.")

if __name__ == "__main__":
    init_database()

