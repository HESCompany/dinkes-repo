@app.route('/analytics')
def analytics():
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
        files_query = File.query.filter(File.upload_date >= threshold)
        
        # Get total counts
        total_files = files_query.count()
        total_users = User.query.count()

        # Get user roles distribution
        user_roles = db.session.query(User.role, db.func.count(User.id)).group_by(User.role).all()
        users_by_role = {role: count for role, count in user_roles}

        # Get file types distribution for the period
        file_types = db.session.query(File.file_type, db.func.count(File.file_type))\
            .filter(File.upload_date >= threshold)\
            .group_by(File.file_type).all()
        files_by_type = {ftype: count for ftype, count in file_types}

        # Get file tags distribution for the period
        file_tags = db.session.query(File.tags, db.func.count(File.tags))\
            .filter(File.upload_date >= threshold)\
            .group_by(File.tags).all()
        files_by_tag = {tag: count for tag, count in file_tags}

        # Get recent uploads
        recent_uploads = files_query.order_by(File.upload_date.desc()).limit(10).all()
        recent_uploads_data = [{
            'filename': file.filename,
            'judul': file.judul,
            'upload_date': file.upload_date.strftime('%Y-%m-%d %H:%M'),
            'file_type': file.file_type,
            'tags': file.tags
        } for file in recent_uploads]

        # Get top downloaded files
        top_files = File.query\
            .filter(File.upload_date >= threshold)\
            .order_by(File.download_count.desc())\
            .limit(10).all()
        top_files_data = [{
            'filename': file.filename,
            'judul': file.judul,
            'download_count': file.download_count or 0,
            'file_type': file.file_type,
            'tags': file.tags
        } for file in top_files]

        # Get visitor statistics
        total_visitors = VisitorLog.query.filter(VisitorLog.timestamp >= threshold).count()

        # Get server performance metrics
        server_perf = get_server_performance()

        return jsonify({
            'total_files': total_files,
            'total_users': total_users,
            'users_by_role': users_by_role,
            'files_by_type': files_by_type,
            'files_by_tag': files_by_tag,
            'recent_uploads': recent_uploads_data,
            'top_files': top_files_data,
            'total_visitors': total_visitors,
            'cpu_usage': server_perf.get('cpu_usage', 0),
            'mem_usage': server_perf.get('mem_usage', 0),
            'period': period
        })
    except Exception as e:
        app.logger.error(f"Error in analytics route: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500 