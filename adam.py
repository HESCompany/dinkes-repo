import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
import uuid

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User

def create_admin_user(email, password):
    with app.app_context():
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            print(f"User {email} already exists.")
            return

        new_admin = User(
            id=str(uuid.uuid4()),
            email=email,
            password_hash=generate_password_hash(password),
            role='admin'
        )
        db.session.add(new_admin)
        db.session.commit()
        print(f"Admin user {email} created successfully.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python adam.py <email> <password>")
        sys.exit(1)

    email = sys.argv[1]
    password = sys.argv[2]

    create_admin_user(email, password)