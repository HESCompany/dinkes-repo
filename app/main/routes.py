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
