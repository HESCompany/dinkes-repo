@app.route('/trend-data')
def trend_data():
    try:
        period = request.args.get('period', 'year')
        
        # Determine if we're using SQLite
        is_sqlite = (db.engine.url.drivername == "sqlite")
        
        # Get current date in UTC
        current_date = datetime.utcnow() if is_sqlite else datetime.now(pytz.utc)
        
        # Calculate date ranges based on period
        if period == 'day':
            end_date = current_date
            start_date = end_date - timedelta(days=1)
            labels = []
            data_points = []
            temp_date = start_date
            while temp_date <= end_date:
                labels.append(temp_date.strftime('%H:00'))
                data_points.append(temp_date)
                temp_date += timedelta(hours=1)
            
            if is_sqlite:
                upload_trend = (
                    db.session.query(
                        func.strftime('%H:00', File.upload_date).label('hour'),
                        func.count(File.id).label('upload_count')
                    )
                    .filter(File.upload_date >= start_date)
                    .group_by('hour')
                    .order_by('hour')
                    .all()
                )
                download_trend = (
                    db.session.query(
                        func.strftime('%H:00', File.upload_date).label('hour'),
                        func.sum(File.download_count).label('download_count')
                    )
                    .filter(File.upload_date >= start_date)
                    .group_by('hour')
                    .order_by('hour')
                    .all()
                )
            else:
                hour_format = '%H:00' if 'mysql' in db.engine.url.drivername else 'HH24:00'
                upload_trend = (
                    db.session.query(
                        func.date_format(File.upload_date, hour_format).label('hour') if 'mysql' in db.engine.url.drivername
                        else func.to_char(File.upload_date, hour_format).label('hour'),
                        func.count(File.id).label('upload_count')
                    )
                    .filter(File.upload_date >= start_date)
                    .group_by('hour')
                    .order_by('hour')
                    .all()
                )
                download_trend = (
                    db.session.query(
                        func.date_format(File.upload_date, hour_format).label('hour') if 'mysql' in db.engine.url.drivername
                        else func.to_char(File.upload_date, hour_format).label('hour'),
                        func.sum(File.download_count).label('download_count')
                    )
                    .filter(File.upload_date >= start_date)
                    .group_by('hour')
                    .order_by('hour')
                    .all()
                )
            
            upload_data = {str(row.hour): row.upload_count for row in upload_trend}
            download_data = {str(row.hour): row.download_count if row.download_count is not None else 0 for row in download_trend}
            
        elif period in ['week', 'month']:
            days_count = 7 if period == 'week' else 30
            end_date = current_date
            start_date = end_date - timedelta(days=days_count - 1)
            
            labels = []
            data_points = []
            temp_date = start_date
            while temp_date <= end_date:
                labels.append(temp_date.strftime('%Y-%m-%d'))
                data_points.append(temp_date)
                temp_date += timedelta(days=1)
            
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
                date_format = '%Y-%m-%d'
                upload_trend = (
                    db.session.query(
                        func.date_format(File.upload_date, date_format).label('day') if 'mysql' in db.engine.url.drivername
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
                        func.date_format(File.upload_date, date_format).label('day') if 'mysql' in db.engine.url.drivername
                        else func.to_char(File.upload_date, 'YYYY-MM-DD').label('day'),
                        func.sum(File.download_count).label('download_count')
                    )
                    .filter(File.upload_date >= start_date)
                    .group_by('day')
                    .order_by('day')
                    .all()
                )
            
            upload_data = {str(row.day): row.upload_count for row in upload_trend}
            download_data = {str(row.day): row.download_count if row.download_count is not None else 0 for row in download_trend}
        
        else:
            end_date = current_date
            start_date = end_date - timedelta(days=365)
            
            labels = []
            current = start_date
            while current <= end_date:
                labels.append(current.strftime('%Y-%m'))
                if current.month == 12:
                    current = current.replace(year=current.year + 1, month=1)
                else:
                    current = current.replace(month=current.month + 1)
            
            if is_sqlite:
                upload_trend = (
                    db.session.query(
                        func.strftime('%Y-%m', File.upload_date).label('month'),
                        func.count(File.id).label('upload_count')
                    )
                    .filter(File.upload_date >= start_date)
                    .group_by('month')
                    .order_by('month')
                    .all()
                )
                download_trend = (
                    db.session.query(
                        func.strftime('%Y-%m', File.upload_date).label('month'),
                        func.sum(File.download_count).label('download_count')
                    )
                    .filter(File.upload_date >= start_date)
                    .group_by('month')
                    .order_by('month')
                    .all()
                )
            else:
                month_format = '%Y-%m'
                upload_trend = (
                    db.session.query(
                        func.date_format(File.upload_date, month_format).label('month') if 'mysql' in db.engine.url.drivername
                        else func.to_char(File.upload_date, 'YYYY-MM').label('month'),
                        func.count(File.id).label('upload_count')
                    )
                    .filter(File.upload_date >= start_date)
                    .group_by('month')
                    .order_by('month')
                    .all()
                )
                download_trend = (
                    db.session.query(
                        func.date_format(File.upload_date, month_format).label('month') if 'mysql' in db.engine.url.drivername
                        else func.to_char(File.upload_date, 'YYYY-MM').label('month'),
                        func.sum(File.download_count).label('download_count')
                    )
                    .filter(File.upload_date >= start_date)
                    .group_by('month')
                    .order_by('month')
                    .all()
                )
            
            upload_data = {str(row.month): row.upload_count for row in upload_trend}
            download_data = {str(row.month): row.download_count if row.download_count is not None else 0 for row in download_trend}
        
        uploads = [upload_data.get(label, 0) for label in labels]
        downloads = [download_data.get(label, 0) for label in labels]
        
        return jsonify({
            "labels": labels,
            "uploads": uploads,
            "downloads": downloads,
            "period": period
        })
        
    except Exception as e:
        app.logger.error(f"Error in trend_data route: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "message": str(e)
        }), 500

@app.route('/analytics/files-by-type')
def analytics_files_by_type():
    try:
        period = request.args.get('period', 'month')
        
        # Calculate date threshold based on period
        now = datetime.utcnow()
        if period == 'day':
            threshold = now - timedelta(days=1)
        elif period == 'week':
            threshold = now - timedelta(days=7)
        elif period == 'month':
            threshold = now - timedelta(days=30)
        elif period == 'year':
            threshold = now - timedelta(days=365)
        else:
            threshold = now - timedelta(days=30)  # Default to month

        # Query files within the period
        query = File.query.filter(File.upload_date >= threshold)
        
        # Group by file_type and count
        file_types = query.with_entities(File.file_type, db.func.count(File.id))\
            .group_by(File.file_type)\
            .order_by(db.func.count(File.id).desc())\
            .all()
        
        data = {ftype if ftype else 'Unknown': count for ftype, count in file_types}
        return jsonify({
            'data': data,
            'period': period
        })
    except Exception as e:
        app.logger.error(f"Error in analytics_files_by_type route: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/analytics/files-by-tag')
def analytics_files_by_tag():
    try:
        period = request.args.get('period', 'month')
        
        # Calculate date threshold based on period
        now = datetime.utcnow()
        if period == 'day':
            threshold = now - timedelta(days=1)
        elif period == 'week':
            threshold = now - timedelta(days=7)
        elif period == 'month':
            threshold = now - timedelta(days=30)
        elif period == 'year':
            threshold = now - timedelta(days=365)
        else:
            threshold = now - timedelta(days=30)  # Default to month

        # Query files within the period
        query = File.query.filter(File.upload_date >= threshold)
        
        # Group by tags and count
        file_tags = query.with_entities(File.tags, db.func.count(File.id))\
            .group_by(File.tags)\
            .order_by(db.func.count(File.id).desc())\
            .all()
        
        data = {tag if tag else 'Uncategorized': count for tag, count in file_tags}
        return jsonify({
            'data': data,
            'period': period
        })
    except Exception as e:
        app.logger.error(f"Error in analytics_files_by_tag route: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/analytics/tag-performance')
def analytics_tag_performance():
    try:
        period = request.args.get('period', 'month')
        
        # Calculate date threshold based on period
        now = datetime.utcnow()
        if period == 'day':
            threshold = now - timedelta(days=1)
        elif period == 'week':
            threshold = now - timedelta(days=7)
        elif period == 'month':
            threshold = now - timedelta(days=30)
        elif period == 'year':
            threshold = now - timedelta(days=365)
        else:
            threshold = now - timedelta(days=30)  # Default to month

        # Query files within the period
        query = File.query.filter(File.upload_date >= threshold)
        
        # Get tag performance data
        tag_data = query.with_entities(
            File.tags,
            db.func.count(File.id).label('upload_count'),
            db.func.sum(File.download_count).label('download_count'),
            db.func.sum(File.view_count).label('view_count')
        ).group_by(File.tags)\
         .order_by(db.func.sum(File.download_count).desc())\
         .all()
        
        data = {}
        for tag, upload_count, download_count, view_count in tag_data:
            tag_name = tag if tag else 'Uncategorized'
            data[tag_name] = {
                "upload_count": upload_count,
                "download_count": download_count if download_count is not None else 0,
                "view_count": view_count if view_count is not None else 0
            }
        
        return jsonify({
            'data': data,
            'period': period
        })
    except Exception as e:
        app.logger.error(f"Error in analytics_tag_performance route: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

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