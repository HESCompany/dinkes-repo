#!/bin/bash

# Create main project directory
mkdir -p file_repository
cd file_repository

# Create app directory and subdirectories
mkdir -p app/{auth,main,templates/{auth,main}}

# Create other necessary directories
mkdir -p migrations uploads

# Create __init__.py files
touch app/__init__.py app/auth/__init__.py app/main/__init__.py

# Create main application files
cat << EOF > app/__init__.py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    return app

from app import models
EOF

cat << EOF > app/models.py
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
EOF

cat << EOF > app/utils.py
import os
from flask import current_app
from werkzeug.utils import secure_filename
from datetime import datetime

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def save_file(file):
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    filename = f"{timestamp}_{filename}"
    file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))
    return filename
EOF

# Create auth module files
cat << EOF > app/auth/__init__.py
from flask import Blueprint

bp = Blueprint('auth', __name__)

from app.auth import routes
EOF

cat << EOF > app/auth/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from app.models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    secret_key = StringField('Secret Key', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')
EOF

cat << EOF > app/auth/routes.py
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required
from app import db
from app.models import User
from app.auth import bp
from app.auth.forms import LoginForm, RegistrationForm
from app.auth.utils import check_registration_secret_key

@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.index'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    return render_template('auth/login.html', title='Login', form=form)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if check_registration_secret_key(form.secret_key.data):
            user = User(username=form.username.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You are now able to log in', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid secret key', 'danger')
    return render_template('auth/register.html', title='Register', form=form)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
EOF

cat << EOF > app/auth/utils.py
from flask import current_app

def check_registration_secret_key(secret_key):
    return secret_key == current_app.config['REGISTRATION_SECRET_KEY']
EOF

# Create main module files
cat << EOF > app/main/__init__.py
from flask import Blueprint

bp = Blueprint('main', __name__)

from app.main import routes
EOF

cat << EOF > app/main/forms.py
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class UploadFileForm(FlaskForm):
    file = FileField('File', validators=[
        FileRequired(),
        FileAllowed(['pdf', 'jpg', 'jpeg', 'png'], 'Only PDF, JPG, JPEG, and PNG files are allowed!')
    ])
    judul = StringField('Judul', validators=[DataRequired()])
    nama_penulis = StringField('Nama Penulis', validators=[DataRequired()])
    nim = StringField('NIM', validators=[DataRequired()])
    university_name = StringField('University Name', validators=[DataRequired()])
    major = StringField('Major', validators=[DataRequired()])
    tags = StringField('Tags', validators=[DataRequired()])
    submit = SubmitField('Upload')
EOF

cat << EOF > app/main/routes.py
from flask import render_template, request, redirect, url_for, flash, send_file, jsonify, abort, current_app
from flask_login import login_required, current_user
from app import db
from app.models import File, User
from app.main import bp
from app.main.forms import UploadFileForm
from app.utils import allowed_file, save_file
import os
from datetime import datetime
import pytz

@bp.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    files = File.query.order_by(File.upload_date.desc()).paginate(page=page, per_page=10)
    return render_template('main/index.html', files=files)

@bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = UploadFileForm()
    if form.validate_on_submit():
        if form.file.data and allowed_file(form.file.data.filename):
            filename = save_file(form.file.data)
            new_file = File(
                filename=filename,
                original_filename=form.file.data.filename,
                file_type=form.file.data.filename.rsplit('.', 1)[1].lower(),
                user_id=current_user.id,
                file_size=os.path.getsize(os.path.join(current_app.config['UPLOAD_FOLDER'], filename)),
                upload_date=datetime.now(pytz.utc),
                nama_penulis=form.nama_penulis.data,
                nim=form.nim.data,
                judul=form.judul.data,
                university_name=form.university_name.data,
                major=form.major.data,
                tags=form.tags.data
            )
            db.session.add(new_file)
            db.session.commit()
            flash('File successfully uploaded', 'success')
            return redirect(url_for('main.index'))
        else:
            flash('File type not allowed', 'danger')
    return render_template('main/upload.html', form=form)

@bp.route('/download/<int:file_id>')
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    return send_file(os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename),
                     download_name=file.original_filename,
                     as_attachment=True)

@bp.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    os.remove(os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename))
    db.session.delete(file)
    db.session.commit()
    flash('File successfully deleted', 'success')
    return redirect(url_for('main.index'))

@bp.route('/file-details/<int:file_id>')
def file_details(file_id):
    file = File.query.get_or_404(file_id)
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
        'uploader_username': file.uploader.username
    })
EOF

# Create template files
cat << EOF > app/templates/base.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}File Repository{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
        <div class="container">
            <a class="navbar-brand" href="{{ url_for('main.index') }}">File Repository</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    {% if current_user.is_authenticated %}
                        <li class="nav-item"><a class="nav-link" href="{{ url_for('main.upload_file') }}">Upload</a></li>
                        <li class="nav-item"><a class="nav-link" href="{{ url_for('auth.logout') }}">Logout</a></li>
                    {% else %}
                        <li class="nav-item"><a class="nav-link" href="{{ url_for('auth.login') }}">Login</a></li>
                        <li class="nav-item"><a class="nav-link" href="{{ url_for('auth.register') }}">Register</a></li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>

    <main class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </main>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOF

cat << EOF > app/templates/auth/login.html
{% extends "base.html" %}

{% block content %}
    <h1>Login</h1>
    <form method="POST">
        {{ form.hidden_tag() }}
        <div class="mb-3">
            {{ form.username.label(class="form-label") }}
            {{ form.username(class="form-control") }}
        </div>
        <div class="mb-3">
            {{ form.password.label(class="form-label") }}
            {{ form.password(class="form-control") }}
        </div>
        <div class="mb-3 form-check">
            {{ form.remember_me(class="form-check-input") }}
            {{ form.remember_me.label(class="form-check-label") }}
        </div>
        {{ form.submit(class="btn btn-primary") }}
    </form>
{% endblock %}
EOF

cat << EOF > app/templates/auth/register.html
{% extends "base.html" %}

{% block content %}
    <h1>Register</h1>
    <form method="POST">
        {{ form.hidden_tag() }}
        <div class="mb-3">
            {{ form.username.label(class="form-label") }}
            {{ form.username(class="form-control") }}
        </div>
        <div class="mb-3">
            {{ form.password.label(class="form-label") }}
            {{ form.password(class="form-control") }}
        </div>
        <div class="mb-3">
            {{ form.confirm_password.label(class="form-label") }}
            {{ form.confirm_password(class="form-control") }}
        </div>
        <div class="mb-3">
            {{ form.secret_key.label(class="form-label") }}
            {{ form.secret_key(class="form-control") }}
        </div>
        {{ form.submit(class="btn btn-primary") }}
    </form>
{% endblock %}
EOF

cat << EOF > app/templates/main/index.html
{% extends "base.html" %}

{% block content %}
    <h1>File Repository</h1>
    <table class="table">
        <thead>
            <tr>
                <th>Title</th>
                <th>Author</th>
                <th>Upload Date</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            {% for file in files.items %}
                <tr>
                    <td>{{ file.judul }}</td>
                    <td>{{ file.nama_penulis }}</td>
                    <td>{{ file.display_upload_date }}</td>
                    <td>
                        <a href="{{ url_for('main.download_file', file_id=file.id) }}" class="btn btn-primary btn-sm">Download</a>
                        {% if current_user.is_authenticated and file.user_id == current_user.id %}
                            <form action="{{ url_for('main.delete_file', file_id=file.id) }}" method="POST" class="d-inline">
                                <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('Are you sure you want to delete this file?');">Delete</button>
                            </form>
                        {% endif %}
                    </td>
                </tr>
            {% endfor %}
        </tbody>
    </table>
    {{ files.links }}
{% endblock %}
EOF

cat << EOF > app/templates/main/upload.html
{% extends "base.html" %}

{% block content %}
    <h1>Upload File</h1>
    <form method="POST" enctype="multipart/form-data">
        {{ form.hidden_tag() }}
        <div class="mb-3">
            {{ form.file.label(class="form-label") }}
            {{ form.file(class="form-control") }}
        </div>
        <div class="mb-3">
            {{ form.judul.label(class="form-label") }}
            {{ form.judul(class="form-control") }}
        </div>
        <div class="mb-3">
            {{ form.nama_penulis.label(class="form-label") }}
            {{ form.nama_penulis(class="form-control") }}
        </div>
        <div class="mb-3">
            {{ form.nim.label(class="form-label") }}
            {{ form.nim(class="form-control") }}
        </div>
        <div class="mb-3">
            {{ form.university_name.label(class="form-label") }}
            {{ form.university_name(class="form-control") }}
        </div>
        <div class="mb-3">
            {{ form.major.label(class="form-label") }}
            {{ form.major(class="form-control") }}
        </div>
        <div class="mb-3">
            {{ form.tags.label(class="form-label") }}
            {{ form.tags(class="form-control") }}
        </div>
        {{ form.submit(class="btn btn-primary") }}
    </form>
{% endblock %}
EOF

# Create configuration file
cat << EOF > config.py
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
EOF

# Create run.py
cat << EOF > run.py
from app import create_app, db
from app.models import User, File

app = create_app()

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'File': File}

if __name__ == '__main__':
    app.run(debug=True)
EOF

# Create requirements.txt
cat << EOF > requirements.txt
Flask==2.3.2
Flask-SQLAlchemy==3.0.3
Flask-Login==0.6.2
Flask-WTF==1.1.1
Flask-Migrate==4.0.4
Werkzeug==2.3.4
pytz==2023.3
python-dotenv==1.0.0
pymysql==1.0.3
cryptography==41.0.1
EOF

# Create .env file (with placeholder values)
cat << EOF > .env
FLASK_SECRET_KEY=your_secret_key_here
MYSQL_URL=mysql://user:password@localhost:3306/file_repository
MYSQLUSER=your_mysql_user
MYSQLPASSWORD=your_mysql_password
MYSQLHOST=localhost
MYSQLPORT=3306
MYSQLDATABASE=file_repository
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=5242880
ALLOWED_FILE_EXTENSIONS=pdf,jpg,jpeg,png
REGISTRATION_SECRET_KEY=your_registration_secret_key
EOF

# Create .gitignore
cat << EOF > .gitignore
# Environment variables
.env

# Uploaded files
uploads/

# Python
__pycache__/
*.py[cod]
*$py.class

# Virtual Environment
venv/
env/
ENV/

# IDE
.vscode/
.idea/

# Logs
*.log
EOF

echo "Project structure initialized successfully!"
echo "Remember to update the .env file with your actual database credentials and secret keys."
echo "To set up the database, run:"
echo "flask db init"
echo "flask db migrate -m 'Initial migration'"
echo "flask db upgrade"
echo "Then start the application with: python run.py"

