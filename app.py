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

# Load configuration from .env
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
DB_USERNAME = os.getenv('DB_USERNAME')
DB_PASSWORD = urllib.parse.quote_plus(os.getenv('DB_PASSWORD'))
DB_HOST = os.getenv('DB_HOST')
DB_NAME = os.getenv('DB_NAME')

# SQLAlchemy database URI
if DB_PASSWORD:
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USERNAME}@{DB_HOST}/{DB_NAME}'

print(f"Connecting to database: {app.config['SQLALCHEMY_DATABASE_URI']}")

# Register PyMySQL as MySQL driver
import pymysql
pymysql.install_as_MySQLdb()

# File upload configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', os.path.join(BASE_DIR, 'uploads'))
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 50 * 1024 * 1024))  # 50 MB

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

@app.route('/')
def index():
    try:
        judul = request.args.get('judul', '').strip()
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        nama_penulis = request.args.get('nama_penulis', '').strip()
        nim = request.args.get('nim', '').strip()
        university_name = request.args.get('university_name', '').strip()
        major = request.args.get('major', '').strip()
        file_type = request.args.get('file_type', '').strip()
        tags = request.args.getlist('tags')
        uploaded_by = request.args.get('uploaded_by', '').strip()

        query = File.query

        if judul:
            query = query.filter(File.judul.ilike(f'%{judul}%'))
        if date_from:
            query = query.filter(File.upload_date >= date_from)
        if date_to:
            query = query.filter(File.upload_date <= date_to)
        if nama_penulis:
            query = query.filter(File.nama_penulis.ilike(f'%{nama_penulis}%'))
        if nim:
            query = query.filter(File.nim.ilike(f'%{nim}%'))
        if university_name:
            query = query.filter(File.university_name.ilike(f'%{university_name}%'))
        if major:
            query = query.filter(File.major.ilike(f'%{major}%'))
        if file_type:
            query = query.filter(File.file_type == file_type)
        if tags:
            for tag in tags:
                query = query.filter(File.tags.ilike(f'%{tag}%'))
        if uploaded_by:
            query = query.join(User).filter(User.username.ilike(f'%{uploaded_by}%'))

        page = request.args.get('page', 1, type=int)
        per_page = 10
        files = query.paginate(page=page, per_page=per_page, error_out=False)

        query_params = {
            'judul': judul,
            'date_from': date_from,
            'date_to': date_to,
            'nama_penulis': nama_penulis,
            'nim': nim,
            'university_name': university_name,
            'major': major,
            'file_type': file_type,
            'tags': tags,
            'uploaded_by': uploaded_by
        }

        return render_template('index.html', files=files, query_params=query_params, available_tags=ALLOWED_TAGS)
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        flash('Terjadi kesalahan saat memuat file.', 'danger')
        return redirect(url_for('index'))

@app.route('/file-details/<int:file_id>')
def file_details(file_id):
    try:
        file = db.session.get(File, file_id)
        if not file:
            return jsonify({'error': 'File tidak ditemukan'}), 404

        return jsonify({
            'id': file.id,
            'judul': file.judul,
            'filename': file.filename,
            'original_filename': file.original_filename,
            'file_type': file.file_type,
            'upload_date': file.upload_date.isoformat(),
            'file_size': file.file_size,
            'nama_penulis': file.nama_penulis,
            'nim': file.nim,
            'university_name': file.university_name,
            'major': file.major,
            'tags': file.tags,
            'uploader_username': file.uploader.username if file.uploader else 'Tidak diketahui'
        })
    except Exception as e:
        logger.error(f"Error in file_details route: {str(e)}")
        return jsonify({'error': 'Terjadi kesalahan saat mengambil detail file'}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    try:
        if 'file' not in request.files:
            flash('Tidak ada bagian file', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('Tidak ada file yang dipilih', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = str(datetime.now().timestamp()) + '_' + file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            logger.debug(f"Menyimpan file ke: {file_path}")
            file.save(file_path)

            nama_penulis = request.form.get('nama_penulis')
            nim = request.form.get('nim')
            judul = request.form.get('judul')
            university_name = request.form.get('university_name')
            major = request.form.get('major')
            tags = request.form.getlist('tags')

            # Validate tags
            valid_tags = [tag for tag in tags if tag in ALLOWED_TAGS]
            tags_string = ','.join(valid_tags)

            new_file = File(
                filename=filename,
                original_filename=file.filename,
                file_type=file.filename.split('.')[-1].lower(),
                user_id=current_user.id,
                file_size=os.path.getsize(file_path),
                upload_date=datetime.now(pytz.utc),
                nama_penulis=nama_penulis,
                nim=nim,
                judul=judul,
                university_name=university_name,
                major=major,
                tags=tags_string
            )

            db.session.add(new_file)
            db.session.commit()
            flash('File berhasil diunggah', 'success')
            return redirect(url_for('index'))
        else:
            flash('Tipe file tidak valid. Tipe yang diizinkan: pdf, jpg, jpeg, png.', 'danger')
            return redirect(request.url)
    except Exception as e:
        logger.error(f"Error during file upload: {str(e)}")
        flash('Terjadi kesalahan saat mengunggah file.', 'danger')
        return redirect(url_for('index'))

@app.route('/preview/<int:file_id>')
def serve_preview(file_id):
    try:
        file = db.session.get(File, file_id)
        if not file:
            abort(404, description="File tidak ditemukan.")

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)

        if not os.path.exists(file_path):
            abort(404, description="File tidak ditemukan.")

        if file.file_type == 'pdf':
            return send_file(file_path, mimetype='application/pdf')
        elif file.file_type in ['jpg', 'jpeg', 'png']:
            return send_file(file_path, mimetype=f'image/{file.file_type}')
        else:
            abort(400, description="Pratinjau tidak tersedia untuk tipe file ini.")
    except Exception as e:
        logger.error(f"Error during file preview: {str(e)}")
        flash('Terjadi kesalahan saat memuat pratinjau.', 'danger')
        return redirect(url_for('index'))

@app.route('/download/<int:file_id>')
def download_file(file_id):
    try:
        file = db.session.get(File, file_id)
        if not file:
            abort(404, description="File tidak ditemukan.")

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)

        if not os.path.exists(file_path):
            flash('File tidak ditemukan.', 'danger')
            return redirect(url_for('index'))

        return send_file(
            file_path,
            download_name=file.original_filename,
            as_attachment=True
        )
    except Exception as e:
        logger.error(f"Error during file download: {str(e)}")
        flash('Terjadi kesalahan saat mengunduh file.', 'danger')
        return redirect(url_for('index'))

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    try:
        file = db.session.get(File, file_id)
        if not file:
            abort(404, description="File tidak ditemukan.")

        if file.user_id != current_user.id:
            flash('Anda tidak memiliki izin untuk menghapus file ini.', 'danger')
            return redirect(url_for('index'))

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.debug(f"File dihapus dari disk: {file_path}")
            else:
                logger.debug(f"File tidak ditemukan di disk: {file_path}")
        except Exception as e:
            logger.error(f"Error deleting file from disk: {str(e)}")
            flash('Terjadi kesalahan saat menghapus file.', 'danger')
            return redirect(url_for('index'))

        db.session.delete(file)
        db.session.commit()
        flash('File berhasil dihapus.', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Error during file deletion: {str(e)}")
        flash('Terjadi kesalahan saat menghapus file.', 'danger')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password'].strip()
            logger.debug(f"Percobaan login - Username: {username}")
            user = User.query.filter_by(username=username).first()
            if user:
                logger.debug(f"Pengguna ditemukan di database: {user.username}")
                is_valid = check_password_hash(user.password_hash, password)
                logger.debug(f"Password valid: {is_valid}")
                if is_valid:
                    login_user(user)
                    return redirect(url_for('index'))
            flash('Username atau password tidak valid', 'danger')
        return render_template('login.html')
    except Exception as e:
        logger.error(f"Error during login: {str(e)}")
        flash('Terjadi kesalahan saat login.', 'danger')
        return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        secret_key = request.form.get('secret_key')
        if secret_key != os.getenv('REGISTRATION_SECRET_KEY'):
            flash('Registrasi gagal: Kunci rahasia tidak valid.', 'danger')
            return render_template('register.html')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Registrasi gagal: Username sudah ada. Silakan pilih username lain.', 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Akun berhasil dibuat! Anda sekarang dapat login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Anda telah berhasil logout.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5010)

