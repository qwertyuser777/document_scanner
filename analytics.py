from flask import jsonify, session, render_template
from sqlalchemy import func, extract
from datetime import datetime, timezone
from collections import Counter
from matching import extract_text

def log_scan(db_session, ScanHistory, user_id, document_id):
    scan = ScanHistory(user_id=user_id, document_id=document_id)
    db_session.add(scan)
    db_session.commit()

def init_analytics_routes(app, db_session, User, ScanHistory, Document):
    def get_daily_scans(db_session, ScanHistory):
        today = datetime.now(timezone.utc).date()
        scans = db_session.query(ScanHistory.user_id, func.count(ScanHistory.id).label('scan_count'))\
            .filter(func.date(ScanHistory.timestamp) == today)\
            .group_by(ScanHistory.user_id)\
            .all()
        total_scans = sum(count for _, count in scans)
        return total_scans, {user_id: count for user_id, count in scans}

    def get_common_topics(db_session, ScanHistory, Document):
        today = datetime.now(timezone.utc).date()
        scans = db_session.query(ScanHistory)\
            .filter(func.date(ScanHistory.timestamp) == today)\
            .all()
        keywords = []
        for scan in scans:
            doc = db_session.query(Document).filter_by(id=scan.document_id).first()
            if doc:
                text = extract_text(doc.filepath)
                words = text.lower().split()
                keywords.extend([word for word in words if len(word) > 3])
        keyword_counts = Counter(keywords).most_common(5)
        return [{'keyword': k, 'count': c} for k, c in keyword_counts]

    def get_top_users(db_session, User, ScanHistory):
        # Total scans per user (credits used = total uploads)
        scans = db_session.query(ScanHistory.user_id, func.count(ScanHistory.id).label('scan_count'))\
            .group_by(ScanHistory.user_id)\
            .all()
        users = db_session.query(User.id, User.username, User.credits).all()
        user_data = {user.id: {'username': user.username, 'current_credits': user.credits} for user in users}
        top_users = [
            {
                'user_id': user_id,
                'username': user_data.get(user_id, {}).get('username', 'Unknown'),
                'scans': scan_count,
                'credits_used': scan_count,  # Credits used = total scans
                'current_credits': user_data.get(user_id, {}).get('current_credits', 0)
            }
            for user_id, scan_count in scans
        ]
        top_users.sort(key=lambda x: x['scans'], reverse=True)
        return top_users[:5]

    def admin_required(func):
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            user = db_session.query(User).filter_by(id=session['user_id']).first()
            from app import ADMIN_USERNAMES
            if user.username not in ADMIN_USERNAMES:
                return jsonify({'error': 'Admin access required'}), 403
            return func(*args, **kwargs)
        wrapper.__name__ = func.__name__
        return wrapper

    @app.route('/admin/analytics', methods=['GET'])
    @admin_required
    def get_analytics():
        total_scans, daily_scans = get_daily_scans(db_session, ScanHistory)
        common_topics = get_common_topics(db_session, ScanHistory, Document)
        top_users = get_top_users(db_session, User, ScanHistory)
        return render_template('admin_analytics.html', 
                               total_scans_today=total_scans,
                               daily_scans=daily_scans,
                               common_topics=common_topics,
                               top_users=top_users)

    init_analytics_routes.log_scan = log_scan

init_analytics_routes.log_scan = log_scan