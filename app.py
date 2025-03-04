from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from functools import wraps
from captcha.image import ImageCaptcha
import secrets
import string
import uuid
import os
import base64
import logging
import pytz
import random
import smtplib
import secrets
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import current_app
import csv
import psutil

app = Flask(__name__)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

WIB = pytz.timezone('Asia/Jakarta')

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

ALLOWED_TAGS = ["Tesis", "Disertasi", "Laporan Penelitian", "Jurnal", "Makalah", "Proposal", "PKL", "Skripsi"]
DOCUMENT_TAGS = ["Tesis", "Disertasi", "Laporan Penelitian", "Jurnal", "Makalah", "Proposal", "PKL", "Skripsi"]

from models import User, File

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403, description="Admin access required")
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_captcha():
    image = ImageCaptcha(width=280, height=90)
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    captcha_image = image.generate(captcha_text)
    captcha_base64 = base64.b64encode(captcha_image.getvalue()).decode()
    return captcha_text, captcha_base64

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.form.get('csrf_token')
        if not token or token != session.get('csrf_token'):
            abort(403, description="Invalid CSRF token")
        return f(*args, **kwargs)
    return decorated_function

def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    try:
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        return False

@app.route('/')
def index():
    return render_template('landing.html')

import psutil
from models import VisitorCounter

from apscheduler.schedulers.background import BackgroundScheduler
import psutil

def log_system_health():
    with app.app_context():
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        new_log = PerformanceLog(cpu_usage=cpu, mem_usage=mem)
        db.session.add(new_log)
        db.session.commit()


scheduler = BackgroundScheduler()
scheduler.add_job(func=log_system_health, trigger="interval", minutes=5)
scheduler.start()

def get_server_performance():
    # Measure CPU and memory usage (psutil must be installed)
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    
    # Get disk usage information
    disk = psutil.disk_usage('/')
    total_disk_gb = disk.total / (1024 * 1024 * 1024)  # Convert bytes to GB
    used_disk_gb = disk.used / (1024 * 1024 * 1024)    # Convert bytes to GB
    total_memory_gb = psutil.virtual_memory().total / (1024 * 1024 * 1024)  # Total memory in GB
    
    return {
        "cpu_usage": cpu, 
        "mem_usage": memory,
        "total_disk_gb": total_disk_gb,
        "used_disk_gb": used_disk_gb,
        "total_memory_gb": total_memory_gb
    }

def get_top_downloaded_files():
    # Assumes your File model has a 'download_count' column (integer)
    # Make sure you update your download route to increment this field.
    top_files = File.query.order_by(File.download_count.desc()).limit(10).all()
    # Return a list of dicts with title and download count
    return [{"title": f.judul, "download_count": f.download_count} for f in top_files]

def get_total_visitors():
    # Assumes you have a VisitorCounter model with a 'count' field
    # If not, create one or use another method to track visitors.
    from models import VisitorCounter  # Ensure this model exists
    visitor = VisitorCounter.query.first()
    return visitor.count if visitor else 0

@app.before_request
def log_visitor():
    # Only log if the request path is exactly '/'
    if request.path == '/':
        try:
            new_log = VisitorLog(
                ip_address=request.remote_addr,
                user_location="Unknown",
                timestamp=datetime.utcnow()
            )
            db.session.add(new_log)
            db.session.commit()
        except Exception as e:
            logger.error(f"Error logging visitor: {e}")



def get_recent_uploads():
    # Get the 10 most recent uploads
    recent_files = File.query.order_by(File.upload_date.desc()).limit(10).all()
    return [{"title": f.judul, "upload_date": f.upload_date.strftime("%d %b %Y")} for f in recent_files]

@app.route('/analytics')
def analytics():
    total_files = File.query.count()
    total_users = User.query.count()

    # Existing analytics queries
    user_roles = db.session.query(User.role, db.func.count(User.id)).group_by(User.role).all()
    users_by_role = {role: count for role, count in user_roles}

    file_types = db.session.query(File.file_type, db.func.count(File.file_type)).group_by(File.file_type).all()
    files_by_type = {ftype: count for ftype, count in file_types}

    file_tags = db.session.query(File.tags, db.func.count(File.tags)).group_by(File.tags).all()
    files_by_tag = {tag: count for tag, count in file_tags}

    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    last_seven_days = File.query.filter(File.upload_date >= seven_days_ago).count()
    
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    last_thirty_days = File.query.filter(File.upload_date >= thirty_days_ago).count()

    # New analytics data
    server_perf = get_server_performance()
    top_downloads = get_top_downloaded_files()
    recent_uploads = get_recent_uploads()
    total_visitors = get_total_visitors()

    return jsonify({
        'total_files': total_files,
        'total_users': total_users,
        'last_seven_days': last_seven_days,
        'last_thirty_days': last_thirty_days,
        'cpu_usage': server_perf["cpu_usage"],
        'mem_usage': server_perf["mem_usage"],
        'top_files': top_downloads,
        'recent_uploads': recent_uploads,
        'total_visitors': total_visitors,
        'users_by_role': users_by_role,
        'files_by_type': files_by_type,
        'files_by_tag': files_by_tag
    })

universities = []

def load_universities():
    global universities
    try:
        with open("allunniv.csv", newline="", encoding="utf-8") as csvfile:
            reader = csv.reader(csvfile)
            next(reader, None)  # Skip header if exists
            universities = [row[0] for row in reader]  # Assuming university name is in first column
        print(f"Loaded {len(universities)} universities.")  # Debugging
    except Exception as e:
        print(f"Error loading university list: {e}")

# Load universities when the app starts
load_universities()

# API to serve the cached university list
@app.route('/universities')
def get_universities():
    return jsonify(universities)

@app.route('/trend-data')
def trend_data():
    from sqlalchemy.sql import func
    import datetime
    from datetime import timedelta
    period = request.args.get('period', 'year')
    
    # Determine if we're using SQLite
    is_sqlite = (db.engine.url.drivername == "sqlite")
    
    if period in ['week', 'month']:
        # For week: last 7 days, for month: last 30 days (including today)
        if is_sqlite:
            # Use naive UTC datetime
            current_date = datetime.datetime.utcnow()
        else:
            current_date = datetime.datetime.now(pytz.utc)
        
        days_count = 7 if period == 'week' else 30
        
        end_date = current_date
        start_date = end_date - timedelta(days=days_count - 1)
        
        # Build a list of day strings (YYYY-MM-DD)
        days = []
        day_iter = start_date
        while day_iter <= end_date:
            days.append(day_iter.strftime('%Y-%m-%d'))
            day_iter += timedelta(days=1)
        
        # Now, filter directly using the datetime objects
        if is_sqlite:
            upload_trend = (
                db.session.query(
                    func.strftime('%Y-%m-%d', File.upload_date).label('day'),
                    func.count(File.id).label('upload_count')
                )
                .filter(File.upload_date >= start_date)
                .group_by('day')
                .order_by('day')
                .all()
            )
            download_trend = (
                db.session.query(
                    func.strftime('%Y-%m-%d', File.upload_date).label('day'),
                    func.sum(File.download_count).label('download_count')
                )
                .filter(File.upload_date >= start_date)
                .group_by('day')
                .order_by('day')
                .all()
            )
        else:
            # For PostgreSQL or MySQL
            upload_trend = (
                db.session.query(
                    func.date_format(File.upload_date, '%Y-%m-%d').label('day') if 'mysql' in db.engine.url.drivername
                    else func.to_char(File.upload_date, 'YYYY-MM-DD').label('day'),
                    func.count(File.id).label('upload_count')
                )
                .filter(File.upload_date >= start_date)
                .group_by('day')
                .order_by('day')
                .all()
            )
            download_trend = (
                db.session.query(
                    func.date_format(File.upload_date, '%Y-%m-%d').label('day') if 'mysql' in db.engine.url.drivername
                    else func.to_char(File.upload_date, 'YYYY-MM-DD').label('day'),
                    func.sum(File.download_count).label('download_count')
                )
                .filter(File.upload_date >= start_date)
                .group_by('day')
                .order_by('day')
                .all()
            )
        
        # Convert query results to dictionaries for easier lookup
        upload_data = {str(row.day): row.upload_count for row in upload_trend}
        download_data = {str(row.day): row.download_count if row.download_count is not None else 0 for row in download_trend}
        
        # Fill in any missing days with zeros
        uploads = [upload_data.get(day, 0) for day in days]
        downloads = [download_data.get(day, 0) for day in days]
        
        return jsonify({
            "labels": days,
            "uploads": uploads,
            "downloads": downloads
        })
    
    else:
        # Yearly view: last 12 full months aggregated by month
        current_date = datetime.datetime.utcnow()
        start_year = current_date.year
        start_month = current_date.month

        months = []
        year, month = start_year, start_month
        for _ in range(12):
            months.append(f"{year}-{month:02d}")
            if month == 1:
                month = 12
                year -= 1
            else:
                month -= 1
        months.reverse()
        threshold_date = datetime.datetime.strptime(months[0], '%Y-%m')
        
        if is_sqlite:
            upload_trend = (
                db.session.query(
                    func.strftime('%Y-%m', File.upload_date).label('month'),
                    func.count(File.id).label('upload_count')
                )
                .filter(File.upload_date >= threshold_date)
                .group_by('month')
                .order_by('month')
                .all()
            )
            download_trend = (
                db.session.query(
                    func.strftime('%Y-%m', File.upload_date).label('month'),
                    func.sum(File.download_count).label('download_count')
                )
                .filter(File.upload_date >= threshold_date)
                .group_by('month')
                .order_by('month')
                .all()
            )
        else:
            # For PostgreSQL or MySQL
            if 'mysql' in db.engine.url.drivername:
                upload_trend = (
                    db.session.query(
                        func.date_format(File.upload_date, '%Y-%m').label('month'),
                        func.count(File.id).label('upload_count')
                    )
                    .filter(File.upload_date >= threshold_date)
                    .group_by('month')
                    .order_by('month')
                    .all()
                )
                download_trend = (
                    db.session.query(
                        func.date_format(File.upload_date, '%Y-%m').label('month'),
                        func.sum(File.download_count).label('download_count')
                    )
                    .filter(File.upload_date >= threshold_date)
                    .group_by('month')
                    .order_by('month')
                    .all()
                )
            else:
                # PostgreSQL
                upload_trend = (
                    db.session.query(
                        func.to_char(File.upload_date, 'YYYY-MM').label('month'),
                        func.count(File.id).label('upload_count')
                    )
                    .filter(File.upload_date >= threshold_date)
                    .group_by('month')
                    .order_by('month')
                    .all()
                )
                download_trend = (
                    db.session.query(
                        func.to_char(File.upload_date, 'YYYY-MM').label('month'),
                        func.sum(File.download_count).label('download_count')
                    )
                    .filter(File.upload_date >= threshold_date)
                    .group_by('month')
                    .order_by('month')
                    .all()
                )
        
        # Convert query results to dictionaries for easier lookup
        upload_data = {str(row.month): row.upload_count for row in upload_trend}
        download_data = {str(row.month): row.download_count if row.download_count is not None else 0 for row in download_trend}
        
        # Fill in any missing months with zeros
        uploads = [upload_data.get(month, 0) for month in months]
        downloads = [download_data.get(month, 0) for month in months]
        
        return jsonify({
            "labels": months,
            "uploads": uploads,
            "downloads": downloads
        })


from datetime import datetime, timedelta
from flask import jsonify
from models import User, File, PerformanceLog, VisitorLog, SearchQuery, LoginAttempt
@app.route('/analytics/visitor-count')
def analytics_visitor_count():
    period = request.args.get('period', 'day')
    WIB = pytz.timezone('Asia/Jakarta')
    
    if period == 'day':
        # For "day": use today's WIB date and group by WIB hour.
        now_wib = datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(WIB)
        today_wib = now_wib.date()
        start_wib = datetime.combine(today_wib, datetime.min.time()).replace(tzinfo=WIB)
        end_wib = datetime.combine(today_wib, datetime.max.time()).replace(tzinfo=WIB)
        start_utc = start_wib.astimezone(pytz.utc)
        end_utc = end_wib.astimezone(pytz.utc)
        logs = VisitorLog.query.filter(VisitorLog.timestamp >= start_utc,
                                       VisitorLog.timestamp <= end_utc).all()
        counts_dict = {str(hour): 0 for hour in range(24)}
        for log in logs:
            log_wib = log.timestamp.replace(tzinfo=pytz.utc).astimezone(WIB)
            hour_str = str(log_wib.hour)
            counts_dict[hour_str] += 1
        labels = [str(i) for i in range(24)]
        counts = [counts_dict[label] for label in labels]
        
    elif period == 'week':
        # For "week": return last 7 days including today.
        now_wib = datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(WIB)
        today_wib = now_wib.date()
        start_date = today_wib - timedelta(days=6)  # 7 days: today and previous 6 days
        end_date = today_wib  # include today
        start_wib = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=WIB)
        end_wib = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=WIB)
        start_utc = start_wib.astimezone(pytz.utc)
        end_utc = end_wib.astimezone(pytz.utc)
        logs = VisitorLog.query.filter(VisitorLog.timestamp >= start_utc,
                                       VisitorLog.timestamp <= end_utc).all()
        counts_dict = {}
        current_date = start_date
        while current_date <= end_date:
            key = current_date.strftime('%Y-%m-%d')
            counts_dict[key] = 0
            current_date += timedelta(days=1)
        for log in logs:
            log_wib = log.timestamp.replace(tzinfo=pytz.utc).astimezone(WIB)
            key = log_wib.strftime('%Y-%m-%d')
            if key in counts_dict:
                counts_dict[key] += 1
        labels = []
        counts = []
        current_date = start_date
        while current_date <= end_date:
            key = current_date.strftime('%Y-%m-%d')
            labels.append(key)
            counts.append(counts_dict.get(key, 0))
            current_date += timedelta(days=1)
        
    elif period == 'month':
        # For "month": last 30 days including today.
        now_wib = datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(WIB)
        today_wib = now_wib.date()
        start_date = today_wib - timedelta(days=29)  # 30 days including today
        end_date = today_wib
        start_wib = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=WIB)
        end_wib = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=WIB)
        start_utc = start_wib.astimezone(pytz.utc)
        end_utc = end_wib.astimezone(pytz.utc)
        logs = VisitorLog.query.filter(VisitorLog.timestamp >= start_utc,
                                       VisitorLog.timestamp <= end_utc).all()
        counts_dict = {}
        current_date = start_date
        while current_date <= end_date:
            key = current_date.strftime('%Y-%m-%d')
            counts_dict[key] = 0
            current_date += timedelta(days=1)
        for log in logs:
            log_wib = log.timestamp.replace(tzinfo=pytz.utc).astimezone(WIB)
            key = log_wib.strftime('%Y-%m-%d')
            if key in counts_dict:
                counts_dict[key] += 1
        labels = []
        counts = []
        current_date = start_date
        while current_date <= end_date:
            key = current_date.strftime('%Y-%m-%d')
            labels.append(key)
            counts.append(counts_dict.get(key, 0))
            current_date += timedelta(days=1)
        
    elif period == 'year':
        # For "year": return last 12 months including the current month.
        now_wib = datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(WIB)
        months = []
        for i in range(11, -1, -1):
            month_date = now_wib - relativedelta(months=i)
            months.append(month_date.strftime('%Y-%m'))
        start_month_str = months[0] + "-01"
        start_wib = datetime.strptime(start_month_str, '%Y-%m-%d').replace(tzinfo=WIB)
        start_utc = start_wib.astimezone(pytz.utc)
        # For MySQL, use DATE_FORMAT instead of date_trunc
        results = db.session.query(
            func.date_format(VisitorLog.timestamp, '%Y-%m').label('month'),
            func.count(VisitorLog.id)
        ).filter(VisitorLog.timestamp >= start_utc)\
         .group_by('month').order_by('month').all()
        counts_dict = {m: 0 for m in months}
        for r in results:
            m_label, count = r
            counts_dict[m_label] = count
        labels = months
        counts = [counts_dict[m] for m in months]
    else:
        labels = []
        counts = []
        
    return jsonify({"labels": labels, "counts": counts})

@app.route('/analytics/files-by-type')
def analytics_files_by_type():
    period = request.args.get('period', 'all')
    query = File.query
    if period == 'week':
        threshold = datetime.utcnow() - timedelta(days=7)
        query = query.filter(File.upload_date >= threshold)
    elif period == 'month':
        threshold = datetime.utcnow() - timedelta(days=30)
        query = query.filter(File.upload_date >= threshold)
    elif period == 'year':
        threshold = datetime.utcnow() - timedelta(days=365)
        query = query.filter(File.upload_date >= threshold)
    # Group by file_type and count
    file_types = query.with_entities(File.file_type, db.func.count(File.id)).group_by(File.file_type).all()
    data = {ftype: count for ftype, count in file_types}
    return jsonify(data)

@app.route('/analytics/files-by-tag')
def analytics_files_by_tag():
    period = request.args.get('period', 'all')
    query = File.query
    if period == 'week':
        threshold = datetime.utcnow() - timedelta(days=7)
        query = query.filter(File.upload_date >= threshold)
    elif period == 'month':
        threshold = datetime.utcnow() - timedelta(days=30)
        query = query.filter(File.upload_date >= threshold)
    elif period == 'year':
        threshold = datetime.utcnow() - timedelta(days=365)
        query = query.filter(File.upload_date >= threshold)
    # Group by tags and count. (Assuming each file has a single tag)
    file_tags = query.with_entities(File.tags, db.func.count(File.id)).group_by(File.tags).all()
    data = {tag: count for tag, count in file_tags}
    return jsonify(data)

import shutil
from datetime import datetime, timedelta

# --- New Endpoints ---

@app.route('/analytics/storage-usage')
def analytics_storage_usage():
    total, used, free = shutil.disk_usage(app.config['UPLOAD_FOLDER'])
    # Convert bytes to megabytes (MB)
    used_mb = used / (1024 * 1024)
    free_mb = free / (1024 * 1024)
    total_mb = total / (1024 * 1024)
    # Optionally, if you want to use GB when appropriate:
    # used_gb = used / (1024 * 1024 * 1024)
    return jsonify({
        "total": total_mb,  # in MB
        "used": used_mb,
        "free": free_mb,
        "unit": "MB"
    })

@app.route('/analytics/tag-performance')
def analytics_tag_performance():
    from datetime import datetime, timedelta
    period = request.args.get('period', 'all')
    query = File.query
    if period == 'week':
        threshold = datetime.utcnow() - timedelta(days=7)
        query = query.filter(File.upload_date >= threshold)
    elif period == 'month':
        threshold = datetime.utcnow() - timedelta(days=30)
        query = query.filter(File.upload_date >= threshold)
    elif period == 'year':
        threshold = datetime.utcnow() - timedelta(days=365)
        query = query.filter(File.upload_date >= threshold)
    tag_data = query.with_entities(
        File.tags,
        db.func.count(File.id).label('upload_count'),
        db.func.sum(File.download_count).label('download_count')
    ).group_by(File.tags).order_by(db.func.sum(File.download_count).desc()).all()
    
    data = {}
    for tag, upload_count, download_count in tag_data:
        data[tag] = {
            "upload_count": upload_count,
            "download_count": download_count if download_count is not None else 0
        }
    return jsonify(data)


@app.route('/analytics/system-health/historical')
def analytics_system_health_historical():
    cutoff = datetime.utcnow() - timedelta(hours=24)
    logs = PerformanceLog.query.filter(PerformanceLog.timestamp >= cutoff).order_by(PerformanceLog.timestamp.asc()).all()
    data = [{"timestamp": log.timestamp.isoformat(), "cpu_usage": log.cpu_usage, "mem_usage": log.mem_usage} for log in logs]
    return jsonify(data)

@app.route('/analytics/visitor-demographics')
def analytics_visitor_demographics():
    period = request.args.get('period', 'day')
    WIB = pytz.timezone('Asia/Jakarta')
    now_wib = datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(WIB)
    
    if period == 'day':
        # Use today’s WIB date
        today_wib = now_wib.date()
        start_wib = datetime.combine(today_wib, datetime.min.time()).replace(tzinfo=WIB)
        end_wib = datetime.combine(today_wib, datetime.max.time()).replace(tzinfo=WIB)
        
    elif period == 'week':
        # Last 7 days including today
        today_wib = now_wib.date()
        start_date = today_wib - timedelta(days=6)  # today + previous 6 days
        start_wib = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=WIB)
        end_wib = datetime.combine(today_wib, datetime.max.time()).replace(tzinfo=WIB)
        
    elif period == 'month':
        # Last 30 days including today
        today_wib = now_wib.date()
        start_date = today_wib - timedelta(days=29)  # 30 days including today
        start_wib = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=WIB)
        end_wib = datetime.combine(today_wib, datetime.max.time()).replace(tzinfo=WIB)
        
    elif period == 'year':
        # Last 12 months (starting from the 1st day of the month 11 months ago) up to today
        # Use relativedelta to subtract months
        month_date = now_wib - relativedelta(months=11)
        start_wib = month_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        today_wib = now_wib.date()
        end_wib = datetime.combine(today_wib, datetime.max.time()).replace(tzinfo=WIB)
        
    else:
        # Fallback to 'day'
        today_wib = now_wib.date()
        start_wib = datetime.combine(today_wib, datetime.min.time()).replace(tzinfo=WIB)
        end_wib = datetime.combine(today_wib, datetime.max.time()).replace(tzinfo=WIB)
    
    # Convert start and end times from WIB to UTC for querying the database.
    start_utc = start_wib.astimezone(pytz.utc)
    end_utc = end_wib.astimezone(pytz.utc)
    
    # Query logs within the UTC range and group by user location.
    data = db.session.query(VisitorLog.user_location, db.func.count(VisitorLog.id))\
                     .filter(VisitorLog.timestamp >= start_utc,
                             VisitorLog.timestamp <= end_utc)\
                     .group_by(VisitorLog.user_location)\
                     .all()
    
    # Filter out entries where the location might be null/empty.
    result = {location: count for location, count in data if location}
    labels = list(result.keys())
    counts = list(result.values())
    
    return jsonify({"labels": labels, "counts": counts})



@app.route('/analytics/search-trends')
def analytics_search_trends():
    data = db.session.query(SearchQuery.query, db.func.count(SearchQuery.id)).group_by(SearchQuery.query).order_by(db.func.count(SearchQuery.id).desc()).limit(10).all()
    result = {query: count for query, count in data}
    return jsonify(result)

@app.route('/analytics/access-control')
def analytics_access_control():
    success_count = db.session.query(db.func.count(LoginAttempt.id)).filter(LoginAttempt.success == True).scalar()
    failure_count = db.session.query(db.func.count(LoginAttempt.id)).filter(LoginAttempt.success == False).scalar()
    
    # Get details for the most recent 50 attempts
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).limit(50).all()
    details = [{
        "user_email": attempt.user_email,
        "success": attempt.success,
        "ip_address": attempt.ip_address,
        "timestamp": attempt.timestamp.isoformat()
    } for attempt in attempts]
    
    return jsonify({
        "success_count": success_count,
        "failure_count": failure_count,
        "attempts": details
    })

@app.route('/repository')
def repository():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        query = File.query

        sort_column = request.args.get('sort', 'upload_date')  # Default sort by upload_date
        sort_order = request.args.get('order', 'desc')  # Default to descending order

        # Validate column name to prevent SQL injection
        valid_columns = ['upload_date', 'nama_penulis', 'nim', 'university_name', 'major', 'judul', 'tags']
        if sort_column not in valid_columns:
            sort_column = 'upload_date'  # Default to a safe column

        # Apply sorting
        if sort_order == 'asc':
            query = query.order_by(getattr(File, sort_column).asc())
        else:
            query = query.order_by(getattr(File, sort_column).desc())

        # Search filters
        judul = request.args.get('judul', '').strip()
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        nama_penulis = request.args.get('nama_penulis', '').strip()
        nim = request.args.get('nim', '').strip()
        university_name = request.args.get('university_name', '').strip()
        major = request.args.get('major', '').strip()
        file_type = request.args.get('file_type', '').strip()
        tags = request.args.get('tags', '').strip()
        uploaded_by_self = request.args.get('uploaded_by_self')

        if judul:
            query = query.filter(File.judul.ilike(f'%{judul}%'))
        if date_from:
            date_from = datetime.strptime(date_from, '%Y-%m-%d').replace(tzinfo=pytz.UTC)
            query = query.filter(File.upload_date >= date_from)
        if date_to:
            date_to = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59, tzinfo=pytz.UTC)
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
            query = query.filter(File.tags.ilike(f'%{tags}%'))
        if uploaded_by_self and current_user.is_authenticated:
            query = query.filter(File.user_id == current_user.id)

        query = query.order_by(File.upload_date.desc())
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)

        search_captcha_text, search_captcha_image = generate_captcha()
        session['search_captcha_text'] = search_captcha_text

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return render_template('_files_list.html', 
                                   pagination=pagination,
                                   query_params=request.args)

        judul = request.args.get('judul', '').strip()
        if judul:
            # Log search query
            new_search = SearchQuery(query=judul, timestamp=datetime.utcnow())
            db.session.add(new_search)
            db.session.commit()
            query = query.filter(File.judul.ilike(f'%{judul}%'))

        return render_template('index.html',
                                pagination=pagination, 
                                available_tags=ALLOWED_TAGS, 
                                query_params=request.args, 
                                search_captcha_image=search_captcha_image)
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        flash('Error loading files', 'error')
        return redirect(url_for('repository'))

@app.route('/admin/edit-file/<string:file_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_file(file_id):
    file = File.query.get_or_404(file_id)
    if request.method == 'POST':
        file.judul = request.form.get('judul')
        file.nama_penulis = request.form.get('nama_penulis')
        file.nim = request.form.get('nim')
        file.university_name = request.form.get('university_name')
        file.major = request.form.get('major')
        file.tags = request.form.get('tags')
        
        db.session.commit()
        flash('File updated successfully', 'success')
        return redirect(url_for('admin_file_management'))
    
    return jsonify({
        'judul': file.judul,
        'nama_penulis': file.nama_penulis,
        'nim': file.nim,
        'university_name': file.university_name,
        'major': file.major,
        'tags': file.tags
    })

@app.route('/admin/create-file', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_create_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = str(datetime.now().timestamp()) + '_' + secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            nim = request.form.get('nim')
            nama_penulis = request.form.get('nama_penulis')
            nama_universitas = request.form.get('nama_universitas')
            prodi = request.form.get('prodi')
            judul = request.form.get('judul')
            tags = request.form.get('tags')

            new_file = File(
                filename=filename,
                original_filename=file.filename,
                file_type=file.filename.rsplit('.', 1)[1].lower(),
                user_id=current_user.id,
                file_size=os.path.getsize(file_path),
                upload_date=datetime.now(pytz.utc),
                nim=nim,
                nama_penulis=nama_penulis,
                university_name=nama_universitas,
                major=prodi,
                judul=judul,
                tags=tags
            )
            db.session.add(new_file)
            db.session.commit()
            flash('File created successfully', 'success')
            return redirect(url_for('admin_file_management'))
        else:
            flash('Invalid file type. Allowed types: pdf, jpg, jpeg, png, docx', 'danger')
            return redirect(url_for('admin_create_file'))
    return render_template('admin/create_file.html', available_tags=DOCUMENT_TAGS)

@app.route('/download/<string:file_id>')
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    file.download_count += 1
    db.session.commit()
    return send_file(
        os.path.join(app.config['UPLOAD_FOLDER'], file.filename),
        as_attachment=True,
        download_name=file.original_filename
    )

@app.before_request
def count_visitor():
    # Only count on the landing page ('/' endpoint)
    if request.endpoint == 'index' and 'visited' not in session:
        visitor = VisitorCounter.query.first()
        if not visitor:
            visitor = VisitorCounter(count=1)
            db.session.add(visitor)
        else:
            visitor.count += 1
        db.session.commit()
        session['visited'] = True

@app.route('/admin/file-management')
@login_required
@admin_required
def admin_file_management():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    query = File.query

    sort_column = request.args.get('sort', 'upload_date')  # Default sort by upload_date
    sort_order = request.args.get('order', 'desc')  # Default to descending order
    # Validate column name to prevent SQL injection
    valid_columns = ['upload_date', 'nama_penulis', 'university_name', 'major', 'judul']
    if sort_column not in valid_columns:
        sort_column = 'upload_date'  # Default to a safe column
    # Apply sorting
    if sort_order == 'asc':
        query = query.order_by(getattr(File, sort_column).asc())
    else:
        query = query.order_by(getattr(File, sort_column).desc())

    # Search filters
    judul = request.args.get('judul', '').strip()
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    nama_penulis = request.args.get('nama_penulis', '').strip()
    nim = request.args.get('nim', '').strip()
    tags = request.args.get('tags', '').strip()
    uploaded_by = request.args.get('uploaded_by', '').strip()

    # Apply filters
    if judul:
        query = query.filter(File.judul.ilike(f'%{judul}%'))
    if date_from:
        query = query.filter(File.upload_date >= datetime.strptime(date_from, '%Y-%m-%d'))
    if date_to:
        query = query.filter(File.upload_date <= datetime.strptime(date_to, '%Y-%m-%d'))
    if nama_penulis:
        query = query.filter(File.nama_penulis.ilike(f'%{nama_penulis}%'))
    if nim:
        query = query.filter(File.nim.ilike(f'%{nim}%'))
    if tags:
        query = query.filter(File.tags.ilike(f'%{tags}%'))
    if uploaded_by:
        query = query.filter(File.user_id == uploaded_by)

    files = query.order_by(File.upload_date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    # Get all users for the "Uploaded by" dropdown
    users = User.query.all()

    return render_template('admin/file_management.html', 
                           pagination=files,
                           query_params=request.args,
                           available_tags=DOCUMENT_TAGS,
                           users=users)

@app.route('/admin/delete-file/<string:file_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_file(file_id):
    file = File.query.get_or_404(file_id)
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
    except Exception as e:
        logger.error(f"File deletion error: {str(e)}")
    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully', 'success')
    return redirect(url_for('admin_file_management'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        captcha_text, captcha_image = generate_captcha()
        session['captcha_text'] = captcha_text
        return render_template('login.html', captcha_image=captcha_image)
    
    email = request.form.get('email')
    password = request.form.get('password')
    captcha = request.form.get('captcha', '').upper()

    if not all([email, password, captcha]):
        flash('All fields must be filled', 'error')
        return redirect(url_for('login'))
    
    if captcha != session.get('captcha_text', ''):
        flash('Invalid CAPTCHA', 'error')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    if user and check_password_hash(user.password_hash, password):
        login_user(user)
        # Log successful attempt
        new_attempt = LoginAttempt(user_email=email, success=True, ip_address=request.remote_addr, timestamp=datetime.utcnow())
        db.session.add(new_attempt)
        db.session.commit()
        flash('Login Successful', 'success')
        return redirect(url_for('repository'))
    else:
        # Log failed attempt
        new_attempt = LoginAttempt(user_email=email, success=False, ip_address=request.remote_addr, timestamp=datetime.utcnow())
        db.session.add(new_attempt)
        db.session.commit()
        flash('Invalid credentials', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
@csrf_protect
def upload_file():
    try:
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = str(datetime.now().timestamp()) + '_' + secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            logger.debug(f"Saving file to: {file_path}")
            file.save(file_path)

            nim = request.form.get('nim')
            nama_penulis = request.form.get('nama_penulis')
            nama_universitas = request.form.get('nama_universitas')
            prodi = request.form.get('prodi')
            judul = request.form.get('judul')
            tags = request.form.get('tags')

            new_file = File(
                filename=filename,
                original_filename=file.filename,
                file_type=file.filename.split('.')[-1].lower(),
                user_id=current_user.id,
                file_size=os.path.getsize(file_path),
                upload_date=datetime.now(pytz.utc),
                nim=nim,
                nama_penulis=nama_penulis,
                university_name=nama_universitas,
                major=prodi,
                judul=judul,
                tags=tags
            )
            db.session.add(new_file)
            db.session.commit()
            flash('File uploaded successfully', 'success')
            return redirect(url_for('repository'))
        else:
            flash('Invalid file type. Allowed types: pdf, docx, jpg, jpeg, png', 'danger')
            return redirect(url_for('repository'))
    except Exception as e:
        logger.error(f"Error uploading file: {str(e)}")
        flash('Error uploading file', 'danger')
        return redirect(url_for('repository'))

@app.route('/preview/<file_id>')
def serve_preview(file_id):
    try:
        file = File.query.get_or_404(file_id)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        if not os.path.exists(file_path):
            abort(404, description="File not found.")

        file_type = file.file_type.lower()
        if file_type == 'pdf':
            return send_file(file_path, mimetype='application/pdf')
        elif file_type in ['jpg', 'jpeg', 'png']:
            return send_file(file_path, mimetype=f'image/{file_type}')
        elif file_type == 'docx':
            try:
                import mammoth
                with open(file_path, "rb") as docx_file:
                    result = mammoth.convert_to_html(docx_file)
                    html_content = result.value  # The generated HTML
                    return html_content
            except Exception as e:
                logger.error(f"Error converting DOCX to HTML: {str(e)}")
                abort(400, description="Error converting DOCX file for preview.")
        else:
            abort(400, description="Preview not available")
    except Exception as e:
        logger.error(f"Error loading preview: {str(e)}")
        flash('Error loading preview.', 'danger')
        return redirect(url_for('index'))

@app.route('/delete/<string:file_id>', methods=['POST'])
@login_required
@csrf_protect
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        flash('Unauthorized', 'error')
        return redirect(url_for('repository'))
    
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
    except Exception as e:
        logger.error(f"File deletion error: {str(e)}")
        flash('Failed to delete file', 'danger')
        return redirect(url_for('repository'))
    
    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully', 'success')
    return redirect(url_for('repository'))

@app.route('/file-details/<string:file_id>')
def file_details(file_id):
    file = File.query.get_or_404(file_id)
    return jsonify({
        'id': file.id,
        'title': file.judul,
        'author': file.nama_penulis,
        'nim': file.nim,
        'university': file.university_name,
        'study_program': file.major,
        'tags': file.tags.split(',') if file.tags else [],
        'upload_date': file.display_upload_date,
        'file_type': file.file_type,
        'file_size': file.file_size,
        'uploaded_by': file.uploader.email
    })

def validate_csrf():
    token = request.form.get('csrf_token')
    return token and token == session.get('csrf_token')

def generate_captcha():
    image = ImageCaptcha(width=280, height=90)
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    captcha_image = image.generate(captcha_text)
    captcha_base64 = base64.b64encode(captcha_image.getvalue()).decode()
    return captcha_text, captcha_base64

@app.route('/reload_search_captcha', methods=['GET'])
def reload_search_captcha():
    search_captcha_text, search_captcha_image = generate_captcha()
    session['search_captcha_text'] = search_captcha_text
    return jsonify({'captcha_image': search_captcha_image})

@app.route('/reload_captcha', methods=['GET'])
def reload_captcha():
    captcha_text, captcha_image = generate_captcha()
    session['captcha_text'] = captcha_text
    return jsonify({'captcha_image': captcha_image})

@app.route('/verify_search_captcha', methods=['POST'])
def verify_search_captcha():
    data = request.get_json()
    user_captcha = data.get('captcha', '').upper()
    if user_captcha == session.get('search_captcha_text', '').upper():
        return jsonify(success=True)
    else:
        return jsonify(success=False)

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    query = User.query

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    sort_column = request.args.get('sort', 'date_added')  # Default sort by upload_date
    sort_order = request.args.get('order', 'desc')  # Default to descending order
    # Validate column name to prevent SQL injection
    valid_columns = ['date_added', 'email', 'role']
    if sort_column not in valid_columns:
        sort_column = 'date_added'  # Default to a safe column
    # Apply sorting
    if sort_order == 'asc':
        query = query.order_by(getattr(User, sort_column).asc())
    else:
        query = query.order_by(getattr(User, sort_column).desc())
    users = query.order_by(User.date_added.desc()).paginate(page=page, per_page=per_page, error_out=False)
    total_users = User.query.count()
    total_files = File.query.count()
    files_by_type = db.session.query(File.file_type, db.func.count(File.id)).group_by(File.file_type).all()
    files_by_tag = db.session.query(File.tags, db.func.count(File.id)).group_by(File.tags).all()
    return render_template('admin/dashboard.html', pagination=users, total_users=total_users, 
                           total_files=total_files, files_by_type=files_by_type, files_by_tag=files_by_tag, query_params=request.args)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')
            admin_password = request.form.get('admin_password')

            # Validate required fields
            if not all([email, password, role, admin_password]):
                flash('All fields are required', 'error')
                return redirect(url_for('admin_dashboard'))

            if not check_password_hash(current_user.password_hash, admin_password):
                flash('Invalid admin password.', 'error')
                return redirect(url_for('admin_dashboard'))            
            # Check if user already exists
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash('Email already registered', 'error')
                return redirect(url_for('admin_dashboard'))
            
            # Create new user
            new_user = User(
                email=email,
                role=role
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.commit()
            
            # Send email notification
            subject = "New User Account Created"
            body = f"""
            <p>A new user account has been created:</p>
            <p>Email: {email}</p>
            <p>Role: {role}</p>
            <p>Temporary Password: {password}</p>
            <p><strong>Important:</strong> Please change your password immediately after your first login.</p>
            """
            send_email(email, subject, body)  # Send to the new user
            
            flash('User created successfully', 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating user: {str(e)}")
            flash('Error creating user', 'error')
            return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/dashboard.html')

@app.route('/admin/edit_user/<string:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        secret_key = request.form.get('secret_key')
        if not check_password_hash(current_user.password_hash, secret_key):
            flash('Invalid admin password.', 'error')
            return redirect(url_for('admin_dashboard'))            

        old_email = user.email
        old_role = user.role

        user.email = request.form.get('email')
        user.role = request.form.get('role')
        new_password = request.form.get('password')
        if new_password:
            user.set_password(new_password)        
        db.session.commit()

        # Send email notification
        subject = "Your Account Has Been Updated"
        body = f"""
        <p>Your account has been updated:</p>
        <p>Email: {user.email}</p>
        <p>Role: {user.role}</p>
        """
        if new_password:
            body += f"""
            <p>Your password has been changed to: {new_password}</p>
            <p><strong>Important:</strong> Please change your password immediately after your next login.</p>
            """
        else:
            body += "<p>Your password has not been changed.</p>"
        
        send_email(user.email, subject, body)

        flash('User updated successfully', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/delete_user/<string:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    # Prevent admin from deleting their own account
    if user.id == current_user.id:
        flash("You cannot delete your own account", "error")
        return redirect(url_for('admin_dashboard'))

    deleted_user_email = user.email
    deleted_user_role = user.role

    try:
        db.session.delete(user)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error deleting user: {str(e)}")
        flash("An error occurred while deleting the user", "error")
        return redirect(url_for('admin_dashboard'))

    # Send email notification
    subject = "User Account Deleted"
    body = f"""
    <p>A user account has been deleted:</p>
    <p>Email: {deleted_user_email}</p>
    <p>Role: {deleted_user_role}</p>
    """
    send_email(deleted_user_email, subject, body)

    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            otp = ''.join(random.choices(string.digits, k=6))
            user.reset_token = otp
            user.reset_token_expiration = datetime.utcnow() + timedelta(minutes=15)
            db.session.commit()
            
            email_body = f"""
            <p>You have requested to reset your password. Your OTP is:</p>
            <h2>{otp}</h2>
            <p>This OTP will expire in 15 minutes.</p>
            <p>If you did not request a password reset, please ignore this email.</p>
            """
            if send_email(email, "Password Reset OTP", email_body):
                flash('An OTP has been sent to your email.', 'info')
            else:
                flash('Failed to send OTP email. Please try again later.', 'error')
        else:
            flash('Email not found', 'error')
        return redirect(url_for('reset_password_confirm'))
    return render_template('reset_password.html')

@app.route('/reset_password_confirm', methods=['GET', 'POST'])
def reset_password_confirm():
    if request.method == 'POST':
        email = request.form.get('email')
        otp = request.form.get('otp')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        user = User.query.filter_by(email=email).first()
        if user is None or user.reset_token != otp or user.reset_token_expiration < datetime.utcnow():
            flash('Invalid or expired OTP', 'error')
            return render_template('reset_password_confirm.html')
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password_confirm.html')
        
        user.set_password(new_password)
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        flash('Your password has been reset successfully', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password_confirm.html')

@app.route('/credits')
def credits():
    contributors = [
        {"name": "Satriya Pratama", "role": "Full Stack", "image": "https://i.dailymail.co.uk/i/pix/2016/05/17/02/3443866F00000578-3593848-image-m-18_1463446900350.jpg"},
        {"name": "Heryawan Eko Saputro", "role": "Full Stack", "image": "https://static.wikia.nocookie.net/defde38f-58b1-45ba-bde1-996c9fa202fe/scale-to-width/755"},
    ]
    return render_template('credits.html', contributors=contributors)

@app.route('/admin/get_user/<string:user_id>')
@login_required
@admin_required
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify({
        'email': user.email,
        'role': user.role
    })

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error/404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('error/403.html'), 403

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)

