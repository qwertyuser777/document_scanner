from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for, render_template
from werkzeug.utils import secure_filename
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker
import os
from datetime import datetime, timezone
import hashlib
import uuid
import json

from credits import init_credit_routes
from matching import init_matching_routes, extract_text, find_similar_documents
from analytics import init_analytics_routes, log_scan

app = Flask(__name__)
app.secret_key = 'e8f5a7b3c2d1f9e0a4b6c8d2e1f3a5b7c9d0e2f4a6b80'

SERVER_ID = str(uuid.uuid4())
print(f"Server started with ID: {SERVER_ID}")

# Load admins from JSON file
with open('admins.json', 'r') as f:
    ADMINS = json.load(f)['admins']
ADMIN_USERNAMES = {admin['username'] for admin in ADMINS}

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'txt'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

engine = create_engine('sqlite:///database.db', echo=False)
Base = declarative_base()
Session = sessionmaker(bind=engine)
db_session = Session()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    credits = Column(Integer, default=20)
    last_reset = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Document(Base):
    __tablename__ = 'documents'
    id = Column(Integer, primary_key=True)
    filename = Column(String, nullable=False)
    filepath = Column(String, nullable=False)
    upload_date = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

class ScanHistory(Base):
    __tablename__ = 'scan_history'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    document_id = Column(Integer, ForeignKey('documents.id'), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)
app.config['engine'] = engine

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(func):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or 'server_id' not in session or session['server_id'] != SERVER_ID:
            session.clear()
            return redirect(url_for('login_page'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def reset_credits_if_needed(user):
    now = datetime.now(timezone.utc)
    last_reset = user.last_reset
    if last_reset.tzinfo is None:
        last_reset = last_reset.replace(tzinfo=timezone.utc)
    if (now - last_reset).days >= 1:
        user.credits = 20
        user.last_reset = now
        db_session.commit()

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')

@app.route('/', methods=['GET'])
@login_required
def index():
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    reset_credits_if_needed(user)
    return render_template('index.html', username=user.username, credits=user.credits)

@app.route('/user/profile', methods=['GET'])
@login_required
def profile():
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    reset_credits_if_needed(user)
    if user.username in ADMIN_USERNAMES:
        requests = db_session.query(CreditRequest).filter_by(status='pending').all()
        request_list = [
            {'id': req.id, 'user_id': req.user_id, 'username': db_session.query(User).filter_by(id=req.user_id).first().username, 'request_date': req.request_date.isoformat()}
            for req in requests
        ]
        print(f"Pending requests: {len(request_list)}")  # Debug log
        return render_template('profile.html', username=user.username, credits=user.credits, is_admin=True, requests=request_list)
    return render_template('profile.html', username=user.username, credits=user.credits, is_admin=False)

@app.route('/user/documents', methods=['GET'])
@login_required
def user_documents():
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    reset_credits_if_needed(user)
    return render_template('documents.html', username=user.username, credits=user.credits)

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if db_session.query(User).filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    password_hash = hash_password(password)
    new_user = User(username=username, password_hash=password_hash)
    db_session.add(new_user)
    db_session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    password_hash = hash_password(password)
    admin_entry = next((admin for admin in ADMINS if admin['username'] == username and admin['password_hash'] == password_hash), None)
    user = db_session.query(User).filter_by(username=username).first()

    if admin_entry:
        if not user:
            user = User(username=username, password_hash=password_hash)
            db_session.add(user)
        else:
            user.password_hash = password_hash
        db_session.commit()
        session['user_id'] = user.id
        session['server_id'] = SERVER_ID
        reset_credits_if_needed(user)
        return jsonify({'message': 'Logged in successfully'}), 200
    elif user and username not in ADMIN_USERNAMES and user.password_hash == password_hash:
        session['user_id'] = user.id
        session['server_id'] = SERVER_ID
        reset_credits_if_needed(user)
        return jsonify({'message': 'Logged in successfully'}), 200
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/auth/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    session.pop('server_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    reset_credits_if_needed(user)
    if user.credits <= 0:
        return jsonify({'error': 'No credits remaining. Request more or wait until midnight.'}), 403
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        new_doc = Document(filename=filename, filepath=filepath, user_id=session['user_id'])
        db_session.add(new_doc)
        user.credits -= 1
        db_session.commit()
        log_scan(db_session, ScanHistory, user.id, new_doc.id)
        text = extract_text(filepath)
        use_ai = request.form.get('use_ai', 'false').lower() == 'true'
        print(f"Backend received use_ai: {use_ai}")
        matches = find_similar_documents(text, db_session, Document, user.id, use_ai=use_ai)
        return jsonify({
            'message': 'File uploaded successfully',
            'filename': filename,
            'matches': matches,
            'credits': user.credits,
            'ai_used': use_ai
        }), 201
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/documents', methods=['GET'])
@login_required
def get_documents():
    docs = db_session.query(Document).filter_by(user_id=session['user_id']).all()
    doc_list = [{'id': doc.id, 'filename': doc.filename, 'upload_date': doc.upload_date.isoformat()} for doc in docs]
    return jsonify(doc_list), 200

@app.route('/download/<int:doc_id>', methods=['GET'])
@login_required
def download_file(doc_id):
    doc = db_session.query(Document).filter_by(id=doc_id, user_id=session['user_id']).first()
    if doc:
        return send_from_directory(app.config['UPLOAD_FOLDER'], doc.filename, as_attachment=True)
    return jsonify({'error': 'File not found or not authorized'}), 404

@app.route('/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete_file(doc_id):
    doc = db_session.query(Document).filter_by(id=doc_id, user_id=session['user_id']).first()
    if doc:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db_session.delete(doc)
        db_session.commit()
        return jsonify({'message': 'File deleted successfully'}), 200
    return jsonify({'error': 'File not found or not authorized'}), 404

@app.route('/api')
def home():
    return jsonify({'message': 'Welcome to Document Scanner API'})

@app.route('/user/credits', methods=['GET'])
@login_required
def get_user_credits():
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    reset_credits_if_needed(user)
    return jsonify({'username': user.username, 'credits': user.credits}), 200

@app.route('/user/is_admin', methods=['GET'])
@login_required
def is_admin():
    user = db_session.query(User).filter_by(id=session['user_id']).first()
    is_admin = user.username in ADMIN_USERNAMES
    return jsonify({'is_admin': is_admin}), 200

init_credit_routes(app, db_session, User, Base)
CreditRequest = init_credit_routes.CreditRequest
init_matching_routes(app, db_session, Document, login_required)
init_analytics_routes(app, db_session, User, ScanHistory, Document)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)