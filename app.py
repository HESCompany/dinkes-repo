import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Import models after initializing db to avoid circular imports
from models import User, File

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    files = File.query.all()
    return render_template('index.html', files=files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        secret_key = request.form.get('secret_key')
        if secret_key != app.config['REGISTRATION_SECRET_KEY']:
            flash('Invalid secret key', 'error')
            return render_template('register.html')
        user = User(username=username, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('index'))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('index'))
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        new_file = File(
            filename=filename,
            title=request.form.get('title'),
            author=request.form.get('author'),
            nim=request.form.get('nim'),
            university=request.form.get('university'),
            study_program=request.form.get('study_program'),
            tags=request.form.get('tags'),
            uploaded_by=current_user.id
        )
        db.session.add(new_file)
        db.session.commit()
        flash('File uploaded successfully', 'success')
    return redirect(url_for('index'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], file.filename), as_attachment=True)

@app.route('/delete/<int:file_id>')
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.uploaded_by != current_user.id:
        flash('You do not have permission to delete this file', 'error')
        return redirect(url_for('index'))
    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully', 'success')
    return redirect(url_for('index'))

@app.route('/file/<int:file_id>')
@login_required
def file_details(file_id):
    file = File.query.get_or_404(file_id)
    return jsonify({
        'title': file.title,
        'upload_date': file.upload_date.strftime('%Y-%m-%d %H:%M:%S'),
        'author': file.author,
        'nim': file.nim,
        'university': file.university,
        'study_program': file.study_program,
        'tags': file.tags,
        'file_type': os.path.splitext(file.filename)[1],
        'file_size': os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], file.filename)) // 1024,
        'uploaded_by': User.query.get(file.uploaded_by).username
    })

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

if __name__ == '__main__':
    app.run(debug=True)