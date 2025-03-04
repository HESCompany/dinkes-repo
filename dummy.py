import os
import sys
import random
import uuid
from datetime import datetime
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db
from models import User, File

# Constants
UPLOAD_FOLDER = app.config["UPLOAD_FOLDER"]
FILE_NAME = "QMLR.pdf"
FILE_PATH = os.path.join(UPLOAD_FOLDER, FILE_NAME)
NUM_ENTRIES = 1000

# Ensure QMLR.pdf exists in the upload folder
if not os.path.exists(FILE_PATH):
    print(f"File {FILE_NAME} not found in {UPLOAD_FOLDER}. Ensure it is uploaded.")
    sys.exit(1)

def generate_dummy_data():
    with app.app_context():
        users = User.query.all()
        if not users:
            print("No users found. Please create users before adding dummy data.")
            return

        for i in range(NUM_ENTRIES):
            random_user = random.choice(users)  # Assign a random user
            
            dummy_file = File(
                id=str(uuid.uuid4()),
                filename=FILE_NAME,
                original_filename=FILE_NAME,
                file_type="pdf",
                user_id=random_user.id,
                file_size=os.path.getsize(FILE_PATH),
                upload_date=datetime.utcnow(),
                nim=f"12345678{i}",
                nama_penulis=f"Author {i}",
                university_name=f"University {random.randint(1, 100)}",
                major=f"Major {random.randint(1, 10)}",
                judul=f"Dummy Research {i}",
                tags=random.choice(["Tesis", "Disertasi", "Jurnal"])
            )
            db.session.add(dummy_file)

        db.session.commit()
        print(f"{NUM_ENTRIES} dummy files added successfully.")

if __name__ == "__main__":
    generate_dummy_data()
