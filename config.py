import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'default-secret-key')
    DATABASE_URL = os.environ.get('MYSQL_URL', 'sqlite:///DKRDB.db')
    if DATABASE_URL.startswith('mysql:'):
        DATABASE_URL = DATABASE_URL.replace('mysql:', 'mysql+pymysql:')
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
    ALLOWED_EXTENSIONS = {'pdf', 'jpg', 'jpeg', 'png'}
    REGISTRATION_SECRET_KEY = os.environ.get('REGISTRATION_SECRET_KEY', 'default-registration-key')