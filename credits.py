from flask import jsonify, request, session
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from datetime import datetime, timezone

def init_credit_routes(app, db_session, User, Base):
    class CreditRequest(Base):
        __tablename__ = 'credit_requests'
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
        request_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
        status = Column(String, default='pending')

    Base.metadata.create_all(app.config['engine'])

    def admin_required(func):
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                return jsonify({'error': 'Authentication required'}), 401
            user = db_session.query(User).filter_by(id=session['user_id']).first()
            from app import ADMIN_USERNAMES  # Import from app
            if user.username not in ADMIN_USERNAMES:
                return jsonify({'error': 'Admin access required'}), 403
            return func(*args, **kwargs)
        wrapper.__name__ = func.__name__
        return wrapper

    @app.route('/credits/request', methods=['POST'])
    def request_credits():
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        user_id = session['user_id']
        existing_request = db_session.query(CreditRequest).filter_by(user_id=user_id, status='pending').first()
        if existing_request:
            return jsonify({'error': 'You already have a pending request'}), 400
        new_request = CreditRequest(user_id=user_id)
        db_session.add(new_request)
        db_session.commit()
        return jsonify({'message': 'Credit request submitted'}), 201

    @app.route('/admin/credits/update', methods=['POST'])
    @admin_required
    def update_credits():
        data = request.get_json()
        request_id = data.get('request_id')
        action = data.get('action')
        credit_request = db_session.query(CreditRequest).filter_by(id=request_id).first()
        if not credit_request:
            return jsonify({'error': 'Request not found'}), 404
        if action == 'approve':
            user = db_session.query(User).filter_by(id=credit_request.user_id).first()
            user.credits += 10
            credit_request.status = 'approved'
        elif action == 'deny':
            credit_request.status = 'denied'
        else:
            return jsonify({'error': 'Invalid action'}), 400
        db_session.commit()
        return jsonify({'message': f'Credit request {action}d'}), 200

    init_credit_routes.CreditRequest = CreditRequest