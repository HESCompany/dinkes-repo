import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('MYSQL_URL') or \
        f"mysql+pymysql://{os.environ.get('MYSQLUSER')}:{os.environ.get('MYSQLPASSWORD')}@" \
        f"{os.environ.get('MYSQLHOST')}:{os.environ.get('MYSQLPORT')}/{os.environ.get('MYSQLDATABASE')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or 'uploads'
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 5 * 1024 * 1024))  # 5 MB default
    ALLOWED_EXTENSIONS = set(os.environ.get('ALLOWED_FILE_EXTENSIONS', 'pdf,jpg,jpeg,png').split(','))
    REGISTRATION_SECRET_KEY = os.environ.get('REGISTRATION_SECRET_KEY')

