from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import pytz
import logging
from dotenv import load_dotenv
import urllib.parse

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'djfkla83747fdjk')

# Database Configuration
# First try Railway's private network MySQL URL
RAILWAY_MYSQL_URL = os.getenv('MYSQL_URL')
if RAILWAY_MYSQL_URL:
    # Replace mysql:// with mysql+pymysql:// for SQLAlchemy
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

# Register PyMySQL as MySQL driver
import pymysql
pymysql.install_as_MySQLdb()

# File upload configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Initialize SQLAlchemy and LoginManager
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Define WIB timezone
WIB = pytz.timezone('Asia/Jakarta')

# Logging configuration
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}

# Allowed tags
ALLOWED_TAGS = ["Tesis", "Disertasi", "Laporan Penelitian", "Jurnal", "Makalah", "Proposal"]

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    files = db.relationship('File', backref='uploader', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    original_filename = db.Column(db.String(200), nullable=False)
    file_type = db.Column(db.String(50))
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_size = db.Column(db.Integer)
    nama_penulis = db.Column(db.String(200))
    nim = db.Column(db.String(50))
    judul = db.Column(db.String(200))
    university_name = db.Column(db.String(200))
    major = db.Column(db.String(200))
    tags = db.Column(db.String(200))

    @property
    def display_upload_date(self):
        return self.upload_date.astimezone(WIB).strftime('%Y-%m-%d %H:%M:%S')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# ... (rest of the code remains the same)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)