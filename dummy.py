import os
import sys
from datetime import datetime, timedelta
import random
import uuid
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from app import app, db, load_universities, university_data
from models import User, File
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

# Generate a random date within the last 7 days
def random_last_week():
    days_ago = random.randint(0, 6)  # Random number of days within the last week
    random_time = timedelta(days=days_ago, hours=random.randint(0, 23), minutes=random.randint(0, 59))
    return datetime.utcnow() - random_time

def generate_dummy_data():
    with app.app_context():
        # Load the university data from CSV
        load_universities()

        users = User.query.all()
        if not users:
            print("No users found. Please create users before adding dummy data.")
            return

        for i in range(NUM_ENTRIES):
            random_user = random.choice(users)  # Assign a random user

            if university_data:
                random_uni = random.choice(list(university_data.keys()))
                random_major = random.choice(university_data[random_uni]) if university_data[random_uni] else "Unknown"
            else:
                random_uni = f"University {random.randint(1, 100)}"
                random_major = f"Major {random.randint(1, 10)}"

            dummy_file = File(
                id=str(uuid.uuid4()),
                filename=FILE_NAME,
                original_filename=FILE_NAME,
                file_type="pdf",
                user_id=random_user.id,
                file_size=os.path.getsize(FILE_PATH),
                upload_date=random_last_week(),  # Assign a random date in the past week
                nim=f"12345678{i}",
                nama_penulis=f"Author {i}",
                university_name=random_uni,
                major=random_major,
                judul=f"Dummy Research {i}",
                tags=random.choice(["Tesis", "Disertasi", "Laporan Penelitian", "Jurnal", "Makalah", "Proposal", "PKL", "Skripsi"])
            )
            db.session.add(dummy_file)

        db.session.commit()
        print(f"{NUM_ENTRIES} dummy files added successfully.")

if __name__ == "__main__":
    generate_dummy_data()
