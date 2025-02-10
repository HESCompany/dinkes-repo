from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pytz

WIB = pytz.timezone('Asia/Jakarta')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    files = db.relationship('File', backref='uploader', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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
    return User.query.get(int(user_id))
