from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
import os
import urllib.parse

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Database Configuration
RAILWAY_MYSQL_URL = os.getenv('MYSQL_URL')
if RAILWAY_MYSQL_URL:
    app.config['SQLALCHEMY_DATABASE_URI'] = RAILWAY_MYSQL_URL.replace("mysql://", "mysql+pymysql://", 1)
else:
    # Fallback to individual connection parameters
    DB_USERNAME = os.getenv('MYSQLUSER', 'root')
    DB_PASSWORD = urllib.parse.quote_plus(os.getenv('MYSQLPASSWORD', 'Hesc0$_@134139'))
    DB_HOST = os.getenv('MYSQLHOST', '127.0.0.1')
    DB_PORT = os.getenv('MYSQLPORT', '3306')
    DB_NAME = os.getenv('MYSQLDATABASE', 'file_repository')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'

print(f"Connecting to database: {app.config['SQLALCHEMY_DATABASE_URI']}")

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    files = db.relationship('File', backref='uploader', lazy=True)

class File(db.Model):
    __tablename__ = 'file'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(200), nullable=False)
    file_type = db.Column(db.String(50))
    upload_date = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_size = db.Column(db.Integer)
    nama_penulis = db.Column(db.String(200))
    nim = db.Column(db.String(50))
    judul = db.Column(db.String(200))
    university_name = db.Column(db.String(200))
    major = db.Column(db.String(200))
    tags = db.Column(db.String(200))

# Database initialization function
def init_db():
    with app.app_context():
        db.create_all()
        print("Database tables created.")

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

# Run this script to initialize the database
print("Initializing database...")
init_db()