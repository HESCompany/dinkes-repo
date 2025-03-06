from flask_login import UserMixin
from datetime import datetime
from app import db
import uuid

class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='regular')
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    auth_token = db.Column(db.String(128))
    reset_token = db.Column(db.String(6))
    reset_token_expiration = db.Column(db.DateTime)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self):
        import secrets
        self.auth_token = secrets.token_urlsafe(32)

# In models.py (or a separate file if preferred)
class VisitorCounter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    count = db.Column(db.Integer, default=0)

class File(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = db.Column(db.String(128), nullable=False)
    original_filename = db.Column(db.String(128), nullable=False)
    judul = db.Column(db.String(128), nullable=False)
    nama_penulis = db.Column(db.String(128), nullable=False)
    nim = db.Column(db.String(20))
    university_name = db.Column(db.String(128))
    major = db.Column(db.String(128))
    tags = db.Column(db.String(256))
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    download_count = db.Column(db.Integer, default=0)
    view_count = db.Column(db.Integer, default=0)  # NEW column
    user_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    uploader = db.relationship('User', backref=db.backref('files', lazy=True))

    @property
    def display_upload_date(self):
        return self.upload_date.strftime('%Y-%m-%d %H:%M:%S')

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(120))
    success = db.Column(db.Boolean)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class SearchQuery(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    query = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class PerformanceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_usage = db.Column(db.Float)
    mem_usage = db.Column(db.Float)

class VisitorLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45))
    user_location = db.Column(db.String(100))  # Populate via IP geolocation if available
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
