import sys
print(f"[VAULTARY] Starting cold-start on Python {sys.version}...", flush=True)

import os
import hashlib
import requests
import secrets
import string
import jwt
import datetime
import urllib.parse

# Ensure datetime.UTC backwards compatibility for Python < 3.11
if not hasattr(datetime, 'UTC'):
    datetime.UTC = datetime.timezone.utc

import pyotp
import qrcode
import io
import base64
import re
import csv
from flask import Flask, render_template, request, jsonify, make_response, url_for, redirect, session, send_from_directory
from zxcvbn import zxcvbn
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.pool import NullPool
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from functools import wraps
from authlib.integrations.flask_client import OAuth
from flask_mail import Mail, Message
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv(override=True)

app = Flask(__name__)
application = app  # WSGI compatibility alias

# --- FIX HTTPS & IP HEADERS ON VERCEL/RENDER ---
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# --- CAPTURE & LOG UNCAUGHT WSGI EXCEPTIONS IN SERVERLESS LOGS ---
class ErrorLoggingMiddleware:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        try:
            return self.wsgi_app(environ, start_response)
        except Exception as e:
            import traceback
            err = traceback.format_exc()
            print(f"[CRITICAL WSGI EXCEPTION]\n{err}", flush=True)
            body = f"Serverless Function Error:\n\n{err}".encode('utf-8')
            start_response('500 Internal Server Error', [
                ('Content-Type', 'text/plain; charset=utf-8'),
                ('Content-Length', str(len(body)))
            ])
            return [body]

app.wsgi_app = ErrorLoggingMiddleware(app.wsgi_app)

CORS(app)

# --- DETECT SERVERLESS ENVIRONMENT (Vercel / AWS Lambda) ---
IS_SERVERLESS = bool(
    os.getenv('VERCEL') or
    os.getenv('VERCEL_ENV') or
    os.getenv('AWS_LAMBDA_FUNCTION_NAME') or
    os.getenv('LAMBDA_TASK_ROOT') or
    os.path.exists('/var/task')
)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'vaultary-fallback-secret-production-key-32b'

app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Handle Supabase/Postgres URL fix (ensure explicit postgresql+psycopg2 driver)
uri = os.getenv('DATABASE_URL')
if uri:
    for prefix in ["postgres://", "postgresql://", "postgresql+psycopg://"]:
        if uri.startswith(prefix):
            uri = "postgresql+psycopg2://" + uri[len(prefix):]
            break

use_sqlite = os.getenv('USE_SQLITE', '').lower() in ['true', '1']

if uri and not use_sqlite and uri.startswith("postgresql"):
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'poolclass': NullPool,
        'pool_pre_ping': True,
        'connect_args': {
            'connect_timeout': 5
        }
    }
    app.config['SQLALCHEMY_DATABASE_URI'] = uri
else:
    # Serverless lambdas (e.g. Vercel) have a strictly read-only filesystem except /tmp
    if IS_SERVERLESS:
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/site.db'
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- SECURITY CONFIG ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "300 per hour"],
    storage_uri="memory://"
)

csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
    'style-src': ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
    'font-src': ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com"],
    'img-src': ["'self'", "data:", "ui-avatars.com", "*.googleusercontent.com", "*.githubusercontent.com", "*.licdn.com", "media.licdn.com", "icons.duckduckgo.com"],
    'connect-src': ["'self'", "cdnjs.cloudflare.com"],
    'object-src': ["'none'"],
    'base-uri': ["'self'"]
}
talisman = Talisman(app, force_https=False, content_security_policy=csp, content_security_policy_nonce_in=['script-src'])

# --- OAUTH KEYS ---
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['GITHUB_CLIENT_ID'] = os.getenv('GITHUB_CLIENT_ID')
app.config['GITHUB_CLIENT_SECRET'] = os.getenv('GITHUB_CLIENT_SECRET')
app.config['LINKEDIN_CLIENT_ID'] = os.getenv('LINKEDIN_CLIENT_ID')
app.config['LINKEDIN_CLIENT_SECRET'] = os.getenv('LINKEDIN_CLIENT_SECRET')

# --- MAIL CONFIG ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

db = SQLAlchemy()
try:
    db.init_app(app)
except Exception as e:
    print(f"[DATABASE INIT ERROR] Failed to initialize with primary URI: {e}", flush=True)
    if 'sqlalchemy' in app.extensions:
        del app.extensions['sqlalchemy']
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/fallback.db' if IS_SERVERLESS else 'sqlite:///site.db'
    db.init_app(app)
bcrypt = Bcrypt(app)
oauth = OAuth(app)
mail = Mail(app)

# --- OAUTH REGISTRATIONS ---
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

github = oauth.register(
    name='github',
    client_id=app.config['GITHUB_CLIENT_ID'],
    client_secret=app.config['GITHUB_CLIENT_SECRET'],
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

linkedin = oauth.register(
    name='linkedin',
    client_id=app.config['LINKEDIN_CLIENT_ID'],
    client_secret=app.config['LINKEDIN_CLIENT_SECRET'],
    server_metadata_url='https://www.linkedin.com/oauth/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'}
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    dob = db.Column(db.String(20), nullable=True)
    profile_pic = db.Column(db.String(200), default="https://ui-avatars.com/api/?name=User")
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    auth_provider = db.Column(db.String(20), default='local')
    two_factor_secret = db.Column(db.String(64), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    duress_pin_hash = db.Column(db.String(128), nullable=True)
    vault_key_salt = db.Column(db.String(64), nullable=True)
    
    # Relationships
    history = db.relationship('History', backref='owner', lazy=True, cascade="all, delete-orphan")
    vault_items = db.relationship('Vault', backref='owner', lazy=True, cascade="all, delete-orphan")
    secure_notes = db.relationship('SecureNote', backref='owner', lazy=True, cascade="all, delete-orphan")
    security_incidents = db.relationship('SecurityIncident', backref='owner', lazy=True, cascade="all, delete-orphan")

class Vault(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(100), nullable=False)
    site_url = db.Column(db.String(200), nullable=True)
    site_username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Contextual Weighting & Security Posture
    criticality = db.Column(db.String(20), default='medium') # 'critical', 'high', 'medium', 'low'
    category = db.Column(db.String(50), default='Logins')
    is_pwned = db.Column(db.Boolean, default=False)
    pwned_count = db.Column(db.Integer, default=0)
    last_pwned_check = db.Column(db.DateTime, nullable=True)
    
    # Deception / Canary Honeypot
    is_canary = db.Column(db.Boolean, default=False)
    canary_fake_pass = db.Column(db.String(100), nullable=True)
    
    # Zero-Knowledge E2EE Support
    encryption_type = db.Column(db.String(30), default='server_fernet') # 'server_fernet' or 'zero_knowledge'
    client_ciphertext = db.Column(db.Text, nullable=True)
    client_iv = db.Column(db.String(64), nullable=True)
    client_salt = db.Column(db.String(64), nullable=True)
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC), onupdate=lambda: datetime.datetime.now(datetime.UTC))
    
    @staticmethod
    def get_encryption_key():
        key = os.getenv('VAULT_KEY') or os.getenv('ENCRYPTION_KEY') or 'dGVzdF9kZWZhdWx0X3ZhdWx0X2tleV8zMmJ5dGVzX2xvbmdfIQ=='
        return key.encode() 

    def set_password(self, plaintext):
        f = Fernet(Vault.get_encryption_key())
        self.encrypted_password = f.encrypt(plaintext.encode())

    def get_password(self):
        if self.is_canary and self.canary_fake_pass:
            return self.canary_fake_pass
        if not self.encrypted_password:
            return ""
        f = Fernet(Vault.get_encryption_key())
        return f.decrypt(self.encrypted_password).decode()

class SecurityIncident(db.Model):
    __tablename__ = 'security_incidents'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    incident_type = db.Column(db.String(50), nullable=False) # 'canary_triggered', 'duress_login', 'breach_detected', 'password_changed'
    severity = db.Column(db.String(20), default='high') # 'critical', 'high', 'medium', 'info'
    details = db.Column(db.Text, nullable=False)
    ip_address = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(200), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    is_acknowledged = db.Column(db.Boolean, default=False)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_score = db.Column(db.Integer, nullable=False)
    checked_on = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class SecureNote(db.Model):
    __tablename__ = 'secure_notes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.Text, nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.datetime.now(datetime.UTC), onupdate=lambda: datetime.datetime.now(datetime.UTC))

    def set_content(self, plaintext):
        f = Fernet(Vault.get_encryption_key())
        self.content = f.encrypt(plaintext.encode('utf-8')).decode('utf-8')

    def get_content(self):
        f = Fernet(Vault.get_encryption_key())
        return f.decrypt(self.content.encode('utf-8')).decode('utf-8')

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token: return jsonify({'message': 'Missing Token'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if data.get('2fa_pending'): return jsonify({'message': '2FA Verification Required'}), 403
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user: return jsonify({'message': 'User not found'}), 401
            current_user.is_duress = data.get('is_duress', False)
        except: return jsonify({'message': 'Invalid Token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if not current_user.is_admin: return jsonify({'message': 'Admin access required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/health')
def health():
    return jsonify({
        'status': 'ok',
        'serverless': IS_SERVERLESS,
        'has_db_url': bool(os.getenv('DATABASE_URL')),
        'has_secret_key': bool(os.getenv('SECRET_KEY')),
        'db_uri_scheme': app.config.get('SQLALCHEMY_DATABASE_URI', '').split(':')[0]
    })

@app.route('/')
def home(): return render_template('index.html')

# --- CUSTOM ERROR HANDLER FOR RATE LIMIT ---
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"message": "Too many attempts. Please wait 1 minute."}), 429

@app.route('/check_username', methods=['POST'])
def check_username():
    data = request.get_json()
    username = data.get('username', '').strip()
    if not username:
        return jsonify({"available": False}), 400
    exists = User.query.filter_by(username=username).first() is not None
    return jsonify({"available": not exists})

@app.route('/check_email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    if not email:
        return jsonify({"available": False}), 400
    exists = User.query.filter_by(email=email).first() is not None
    return jsonify({"available": not exists})

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    
    if not data.get('email'):
        return jsonify({'message': 'Email is required for password recovery.'}), 400

    if not re.match("^[a-zA-Z0-9_]*$", data['username']):
        return jsonify({'message': 'Username can only contain letters, numbers, and underscores.'}), 400

    if User.query.filter((User.username == data['username']) | (User.email == data.get('email'))).first():
        return jsonify({'message': 'Username or Email already exists'}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    is_first_user = User.query.first() is None
    phone = data.get('phone', '')
    dob = data.get('dob', '')

    # --- SERVER SIDE VALIDATION ---
    if phone and not re.match(r'^\d{10}$', phone):
        return jsonify({'message': 'Phone number must be exactly 10 digits.'}), 400

    if not dob:
        return jsonify({'message': 'Date of Birth is required.'}), 400
    
    try:
        day, month, year = map(int, dob.split('/'))
        birth_date = datetime.date(year, month, day)
        today = datetime.date.today()
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        
        if birth_date > today:
            return jsonify({'message': 'Date of birth cannot be in the future.'}), 400
        if age < 13:
            return jsonify({'message': 'You must be at least 13 years old to register.'}), 400
        if age > 120:
            return jsonify({'message': 'Please enter a valid date of birth.'}), 400
    except ValueError:
        return jsonify({'message': 'Invalid Date of Birth format (DD/MM/YYYY).'}), 400

    new_user = User(
        username=data['username'], 
        email=data['email'], 
        password=hashed_password, 
        phone=phone,
        dob=dob,
        is_admin=is_first_user, 
        is_verified=False, 
        auth_provider='local', 
        profile_pic=f"https://ui-avatars.com/api/?name={data['username']}&background=random"
    )
    
    try:
        db.session.add(new_user)
        db.session.commit()
        try:
            token = jwt.encode({'email': new_user.email, 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
            if isinstance(token, bytes): token = token.decode('utf-8')
            verify_url = url_for('verify_email', token=token, _external=True)
            msg = Message('Verify Your Vaultary Account', sender=app.config['MAIL_USERNAME'], recipients=[new_user.email])
            msg.body = f'Welcome to Vaultary! Please click this link to verify your email: {verify_url}'
            mail.send(msg)
            return jsonify({'message': 'Account created! Check your email.'})
        except: return jsonify({'message': 'Account created! (Email failed)'})
    except Exception as e: return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/verify/<token>')
def verify_email(token):
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user = User.query.filter_by(email=data['email']).first()
        if user:
            user.is_verified = True
            db.session.commit()
            return "<h1>Email Verified! Login now.</h1>"
    except: return "<h1>Invalid Token</h1>"
    return "<h1>User not found</h1>"

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    
    # --- ALLOW LOGIN WITH USERNAME OR EMAIL ---
    user = User.query.filter(
        (User.username == data['username']) | (User.email == data['username'])
    ).first()
    
    # --- CHECK FOR DURESS / PANIC PIN (DECEPTION DECOY MODE) ---
    if user and user.duress_pin_hash and bcrypt.check_password_hash(user.duress_pin_hash, data['password']):
        ip = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
        ua = request.headers.get('User-Agent', 'Unknown')[:200]
        try:
            incident = SecurityIncident(
                user_id=user.id,
                incident_type='duress_login',
                severity='critical',
                details=f"Duress / Panic PIN activated from IP {ip}. Decoy vault active.",
                ip_address=ip,
                user_agent=ua
            )
            db.session.add(incident)
            db.session.commit()
            
            # Silent notification if mail configured
            if app.config.get('MAIL_USERNAME') and user.email:
                msg = Message("🚨 SECURITY ALERT: Duress PIN Activated", sender=app.config['MAIL_USERNAME'], recipients=[user.email])
                msg.body = f"A Duress / Panic PIN login was triggered on your Vaultary account.\n\nTime: {datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\nIP Address: {ip}\nUser-Agent: {ua}\n\nThe system has locked down sensitive vaults and displayed the sanitized decoy vault."
                mail.send(msg)
        except Exception:
            pass

        token = jwt.encode({'user_id': user.id, 'is_duress': True, 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
        if isinstance(token, bytes): token = token.decode('utf-8')
        resp = make_response(jsonify({'status': 'success', 'message': 'Login successful', 'token': token, 'is_admin': False, 'is_duress': True}))
        resp.set_cookie('token', token, httponly=True, secure=False, samesite='Lax')
        return resp

    if user and bcrypt.check_password_hash(user.password, data['password']):
        # --- BLOCK LOGIN IF NOT VERIFIED ---
        if not user.is_verified:
            return jsonify({'message': 'Please verify your email first! Check your inbox.'}), 401

        if user.is_2fa_enabled:
            temp_token = jwt.encode({'user_id': user.id, '2fa_pending': True, 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=5)}, app.config['SECRET_KEY'], algorithm="HS256")
            if isinstance(temp_token, bytes): temp_token = temp_token.decode('utf-8')
            return jsonify({'status': '2fa_required', 'temp_token': temp_token})
            
        token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
        if isinstance(token, bytes): token = token.decode('utf-8')
        resp = make_response(jsonify({'status': 'success', 'message': 'Login successful', 'token': token, 'is_admin': user.is_admin}))
        resp.set_cookie('token', token, httponly=True, secure=False, samesite='Lax')
        return resp
        
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/login/verify_2fa', methods=['POST'])
@limiter.limit("5 per minute")
def login_verify_2fa():
    data = request.get_json()
    try:
        decoded = jwt.decode(data.get('temp_token'), app.config['SECRET_KEY'], algorithms=["HS256"])
        if not decoded.get('2fa_pending'): return jsonify({'message': 'Invalid flow'}), 400
        
        user = User.query.get(decoded['user_id'])
        if not user: return jsonify({'message': 'User not found'}), 404
        if not user.two_factor_secret: return jsonify({'message': '2FA not set up'}), 400
        
        totp = pyotp.TOTP(user.two_factor_secret)
        code = str(data.get('code', '')).replace(' ', '')
        
        if totp.verify(code, valid_window=2):
            token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
            if isinstance(token, bytes): token = token.decode('utf-8')
            resp = make_response(jsonify({'status': 'success', 'token': token, 'username': user.username, 'is_admin': user.is_admin}))
            resp.set_cookie('token', token, httponly=True, secure=False, samesite='Lax')
            return resp
        else: return jsonify({'message': 'Invalid Code'}), 400
    except: return jsonify({'message': 'Session expired'}), 401

@app.route('/2fa/setup', methods=['POST'])
@token_required
def setup_2fa(current_user):
    secret = pyotp.random_base32()
    current_user.two_factor_secret = secret
    db.session.commit()
    
    # --- FIX: Removed incorrect '.totp' property usage ---
    uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="Vaultary")
    
    img = qrcode.make(uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return jsonify({'secret': secret, 'qr_image': f"data:image/png;base64,{img_str}"})

@app.route('/2fa/enable', methods=['POST'])
@token_required
def enable_2fa_confirm(current_user):
    data = request.get_json()
    if not current_user.two_factor_secret: return jsonify({'message': 'Setup first'}), 400
    
    totp = pyotp.TOTP(current_user.two_factor_secret)
    code = str(data.get('code', '')).replace(' ', '')
    
    if totp.verify(code, valid_window=2):
        current_user.is_2fa_enabled = True
        db.session.commit()
        return jsonify({'message': '2FA Enabled!'})
    else: return jsonify({'message': 'Invalid Code'}), 400

@app.route('/2fa/disable', methods=['POST'])
@token_required
def disable_2fa(current_user):
    current_user.is_2fa_enabled = False
    current_user.two_factor_secret = None
    db.session.commit()
    return jsonify({'message': '2FA Disabled'})

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()
    if not user: return jsonify({'success': True})
    
    # --- ONE-TIME USE TRICK: Sign with current password hash ---
    dynamic_secret = app.config['SECRET_KEY'] + user.password
    token = jwt.encode(
        {'reset_email': user.email, 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=10)}, 
        dynamic_secret,
        algorithm="HS256"
    )
    if isinstance(token, bytes): token = token.decode('utf-8')
    
    link = url_for('home', reset_token=token, _external=True)
    try:
        msg = Message('Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
        msg.body = f"Reset link (Valid for 10 mins): {link}"
        mail.send(msg)
    except: return jsonify({'message': 'Error sending email'}), 500
    return jsonify({'success': True})

@app.route('/reset_password_confirm', methods=['POST'])
def reset_password_confirm():
    data = request.get_json()
    token = data.get('token')
    try:
        # Decode without verification first just to find the user
        unverified = jwt.decode(token, options={"verify_signature": False})
        user = User.query.filter_by(email=unverified['reset_email']).first()
        
        if not user: return jsonify({'message': 'User not found'}), 404
        
        # Verify with the Dynamic Secret (Old Password Hash)
        dynamic_secret = app.config['SECRET_KEY'] + user.password
        jwt.decode(token, dynamic_secret, algorithms=["HS256"])
        
        # Update Password (this invalidates the token)
        user.password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
        db.session.commit()
        return jsonify({'message': 'Success!'})
        
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Link expired.'}), 400
    except: return jsonify({'message': 'Invalid link.'}), 400

# --- SOCIAL LOGIN ROUTES ---

def generate_unique_username(base_name):
    # Remove spaces and keep only allowed chars (letters, numbers, underscores)
    clean_name = re.sub(r'[^a-zA-Z0-9_]', '', base_name)
    if not clean_name: clean_name = f"User{secrets.token_hex(3)}"
    
    # Truncate to ensure room for suffix
    clean_name = clean_name[:40]
    
    if not User.query.filter_by(username=clean_name).first():
        return clean_name
        
    # Start checking from 100
    counter = 100
    while True:
        new_name = f"{clean_name}{counter}"
        if not User.query.filter_by(username=new_name).first():
            return new_name
        counter += 1

@app.route('/login/google')
def google_login(): return google.authorize_redirect(url_for('google_callback', _external=True))

@app.route('/google/callback')
def google_callback():
    token = google.authorize_access_token()
    user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()
    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        # --- CHECK IF THIS IS THE FIRST USER ---
        is_first_user = User.query.first() is None
        
        # --- FIX: Handle Duplicate Usernames ---
        base_username = user_info.get('name', user_info['email'].split('@')[0])
        username = generate_unique_username(base_username)

        dummy = bcrypt.generate_password_hash(secrets.token_urlsafe(16)).decode('utf-8')
        user = User(
            username=username, 
            email=user_info['email'], 
            password=dummy, 
            is_verified=True, 
            auth_provider='google', 
            profile_pic=user_info.get('picture', f"https://ui-avatars.com/api/?name={username}"),
            is_admin=is_first_user # Set Admin if first user
        )
        db.session.add(user)
        db.session.commit()
    token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
    if isinstance(token, bytes): token = token.decode('utf-8')
    resp = make_response(redirect('/'))
    resp.set_cookie('token', token, httponly=True, secure=False, samesite='Lax')
    resp.set_cookie('social_login_user', user.username, max_age=10, secure=False, samesite='Lax')
    resp.set_cookie('social_login_admin', str(user.is_admin).lower(), max_age=10, secure=False, samesite='Lax')
    return resp

@app.route('/login/github')
def github_login():
    return github.authorize_redirect(url_for('github_callback', _external=True, _scheme='https'))

@app.route('/login/github/callback')
def github_callback():
    token = github.authorize_access_token()
    resp = github.get('user').json()
    email = resp.get('email') or f"{resp['login']}@github.com"
    
    user = User.query.filter_by(email=email).first()
    if not user:
        # --- CHECK IF THIS IS THE FIRST USER ---
        is_first_user = User.query.first() is None
        
        # --- FIX: Handle Duplicate Usernames ---
        base_username = resp['login']
        username = generate_unique_username(base_username)

        dummy = bcrypt.generate_password_hash(secrets.token_urlsafe(16)).decode('utf-8')
        user = User(
            username=username, 
            email=email, 
            password=dummy, 
            is_verified=True, 
            auth_provider='github', 
            profile_pic=resp['avatar_url'],
            is_admin=is_first_user # Set Admin if first user
        )
        db.session.add(user)
        db.session.commit()
    
    jwt_token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
    if isinstance(jwt_token, bytes): jwt_token = jwt_token.decode('utf-8')
    response = make_response(redirect('/'))
    response.set_cookie('token', jwt_token, httponly=True, secure=False, samesite='Lax')
    response.set_cookie('social_login_user', user.username, max_age=10, secure=False, samesite='Lax')
    response.set_cookie('social_login_admin', str(user.is_admin).lower(), max_age=10, secure=False, samesite='Lax')
    return response

@app.route('/login/linkedin')
def linkedin_login():
    # --- FORCE HTTPS SCHEME HERE ---
    return linkedin.authorize_redirect(url_for('linkedin_callback', _external=True, _scheme='https'), scope='openid profile email')

@app.route('/login/linkedin/callback')
def linkedin_callback():
    try:
        token = linkedin.authorize_access_token()
        user_info = linkedin.userinfo()
        if not user_info or not user_info.get('email'):
            return jsonify({'message': 'Failed to fetch user info. Ensure "Sign In with LinkedIn using OpenID Connect" is enabled in LinkedIn Developer Portal.'}), 400
    except Exception as e: return jsonify({'message': f'LinkedIn Login Error: {str(e)}'}), 400
    
    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        # --- CHECK IF THIS IS THE FIRST USER ---
        is_first_user = User.query.first() is None
        
        # --- FIX: Handle Duplicate Usernames ---
        base_username = user_info.get('name', user_info['email'].split('@')[0])
        username = generate_unique_username(base_username)

        dummy = bcrypt.generate_password_hash(secrets.token_urlsafe(16)).decode('utf-8')
        user = User(
            username=username, 
            email=user_info['email'], 
            password=dummy, 
            is_verified=True, 
            auth_provider='linkedin', 
            profile_pic=user_info.get('picture') or f"https://ui-avatars.com/api/?name={user_info.get('name', 'User')}&background=random",
            is_admin=is_first_user # Set Admin if first user
        )
        db.session.add(user)
        db.session.commit()
        
    jwt_token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm="HS256")
    if isinstance(jwt_token, bytes): jwt_token = jwt_token.decode('utf-8')
    response = make_response(redirect('/'))
    response.set_cookie('token', jwt_token, httponly=True, secure=False, samesite='Lax')
    response.set_cookie('social_login_user', user.username, max_age=10, secure=False, samesite='Lax')
    response.set_cookie('social_login_admin', str(user.is_admin).lower(), max_age=10, secure=False, samesite='Lax')
    return response

@app.route('/logout')
def logout():
    resp = make_response(jsonify({'message': 'Logged out'}))
    resp.set_cookie('token', '', expires=0)
    return resp

@app.route('/profile', methods=['GET', 'PUT', 'DELETE'])
@token_required
def profile(current_user):
    if request.method == 'GET':
        return jsonify({
            'username': current_user.username,
            'email': current_user.email or '',
            'phone': current_user.phone or '',
            'dob': current_user.dob or '',
            'profile_pic': current_user.profile_pic,
            'is_admin': current_user.is_admin,
            'is_2fa_enabled': current_user.is_2fa_enabled,
            'auth_provider': current_user.auth_provider
        })
    if request.method == 'PUT':
        data = request.get_json() or {}
        
        # --- USERNAME UPDATE ---
        new_username = data.get('username', '').strip()
        if new_username and new_username != current_user.username:
            if not re.match("^[a-zA-Z0-9_]*$", new_username):
                return jsonify({'message': 'Username: letters, numbers, underscores only.'}), 400
            if User.query.filter_by(username=new_username).first():
                return jsonify({'message': 'Username already taken.'}), 400
            current_user.username = new_username

        # --- EMAIL UPDATE ---
        new_email = data.get('email', '').strip().lower()
        if new_email and new_email != (current_user.email or '').lower():
            if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', new_email):
                return jsonify({'message': 'Invalid email format.'}), 400
            existing_user = User.query.filter_by(email=new_email).first()
            if existing_user and existing_user.id != current_user.id:
                return jsonify({'message': 'Email address already registered by another account.'}), 400
            current_user.email = new_email
        
        # --- PHONE & DOB UPDATE ---
        raw_phone = data.get('phone')
        if raw_phone is not None:
            clean_phone = str(raw_phone).strip()
            if clean_phone:
                if not re.match(r'^\d{10}$', clean_phone):
                    return jsonify({'message': 'Phone number must be exactly 10 digits.'}), 400
                current_user.phone = clean_phone
            else:
                current_user.phone = None
            
        raw_dob = data.get('dob')
        if raw_dob is not None:
            clean_dob = str(raw_dob).strip()
            if clean_dob:
                try:
                    day, month, year = map(int, clean_dob.split('/'))
                    birth_date = datetime.date(year, month, day)
                    today = datetime.date.today()
                    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                    if birth_date > today: return jsonify({'message': 'Date of birth cannot be in the future.'}), 400
                    if age < 13: return jsonify({'message': 'You must be at least 13 years old.'}), 400
                    if age > 120: return jsonify({'message': 'Please enter a valid date of birth.'}), 400
                    current_user.dob = clean_dob
                except (ValueError, IndexError):
                    return jsonify({'message': 'Invalid Date format. Use DD/MM/YYYY.'}), 400
            else:
                current_user.dob = None

        db.session.commit()
        return jsonify({
            'message': 'Profile updated successfully!',
            'username': current_user.username,
            'email': current_user.email or '',
            'phone': current_user.phone or '',
            'dob': current_user.dob or ''
        })
    if request.method == 'DELETE':
        db.session.delete(current_user)
        db.session.commit()
        resp = make_response(jsonify({'message': 'Deleted'}))
        resp.set_cookie('token', '', expires=0)
        return resp

@app.route('/change_password', methods=['PUT'])
@limiter.limit("5 per minute")
@token_required
def change_password(current_user):
    data = request.get_json()
    current_pass = data.get('current_password')
    new_pass = data.get('new_password')
    confirm_pass = data.get('confirm_password')

    if not current_pass or not new_pass or not confirm_pass:
        return jsonify({'message': 'All password fields are required.'}), 400

    if not bcrypt.check_password_hash(current_user.password, current_pass):
        return jsonify({'message': 'Incorrect current password.'}), 401

    if new_pass != confirm_pass:
        return jsonify({'message': 'New passwords do not match.'}), 400

    if len(new_pass) < 8:
        return jsonify({'message': 'New password must be at least 8 characters long.'}), 400

    if bcrypt.check_password_hash(current_user.password, new_pass):
        return jsonify({'message': 'New password cannot be the same as the current password.'}), 400

    if new_pass == current_user.email or new_pass == current_user.username:
        return jsonify({'message': 'New password cannot be your email or username.'}), 400

    # Hash and save
    current_user.password = bcrypt.generate_password_hash(new_pass).decode('utf-8')
    db.session.commit()

    # Create audit log entry
    try:
        with open('security_audit.log', 'a') as f:
            f.write(f"PASSWORD_CHANGED\n{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\nIP: {request.remote_addr}\nUser ID: {current_user.id}\n\n")
    except Exception as e:
        pass # Silently fail log creation if file permissions issue

    # Invalidate session
    resp = make_response(jsonify({'message': 'Password changed successfully.'}))
    resp.set_cookie('token', '', expires=0)
    return resp

# --- VAULT ROUTES ---
@app.route('/vault', methods=['GET', 'POST'])
@token_required
def manage_vault(current_user):
    if request.method == 'GET':
        # Check Decoy / Duress Mode
        if getattr(current_user, 'is_duress', False):
            return jsonify([
                {
                    'id': 99991, 'site_name': 'Netflix', 'site_url': 'https://netflix.com',
                    'site_username': 'personal_user@gmail.com', 'password': 'Password123!',
                    'criticality': 'low', 'category': 'Entertainment', 'is_canary': False,
                    'is_pwned': False, 'pwned_count': 0, 'encryption_type': 'server_fernet',
                    'created_at': '2026-01-10T10:00:00Z', 'updated_at': '2026-01-10T10:00:00Z'
                },
                {
                    'id': 99992, 'site_name': 'Spotify', 'site_url': 'https://spotify.com',
                    'site_username': 'music_fan_99', 'password': 'RockMusic2026$',
                    'criticality': 'low', 'category': 'Entertainment', 'is_canary': False,
                    'is_pwned': False, 'pwned_count': 0, 'encryption_type': 'server_fernet',
                    'created_at': '2026-02-14T12:00:00Z', 'updated_at': '2026-02-14T12:00:00Z'
                },
                {
                    'id': 99993, 'site_name': 'Duolingo', 'site_url': 'https://duolingo.com',
                    'site_username': 'polyglot_user', 'password': 'LearnSpanish#2026',
                    'criticality': 'low', 'category': 'Personal', 'is_canary': False,
                    'is_pwned': False, 'pwned_count': 0, 'encryption_type': 'server_fernet',
                    'created_at': '2026-03-01T15:30:00Z', 'updated_at': '2026-03-01T15:30:00Z'
                }
            ])

        items = Vault.query.filter_by(user_id=current_user.id).all()
        output = []
        for item in items:
            try:
                decrypted = item.get_password()
            except Exception:
                decrypted = ""
            
            created_str = item.created_at.isoformat() if item.created_at else None
            updated_str = item.updated_at.isoformat() if item.updated_at else created_str

            output.append({
                'id': item.id,
                'site_name': item.site_name,
                'site_url': item.site_url,
                'site_username': item.site_username,
                'password': decrypted,
                'criticality': item.criticality or 'medium',
                'category': item.category or 'Logins',
                'is_pwned': bool(item.is_pwned),
                'pwned_count': item.pwned_count or 0,
                'is_canary': bool(item.is_canary),
                'encryption_type': item.encryption_type or 'server_fernet',
                'client_ciphertext': item.client_ciphertext,
                'client_iv': item.client_iv,
                'client_salt': item.client_salt,
                'created_at': created_str,
                'updated_at': updated_str
            })
        return jsonify(output)

    if request.method == 'POST':
        data = request.get_json()
        if not data.get('site_name') or not data.get('site_username'):
            return jsonify({'message': 'Site name and username are required.'}), 400

        is_canary = bool(data.get('is_canary', False))
        canary_fake_pass = data.get('canary_fake_pass')
        if is_canary and not canary_fake_pass:
            canary_fake_pass = 'vlt_sec_' + secrets.token_hex(8)

        enc_type = data.get('encryption_type', 'server_fernet')

        new_item = Vault(
            site_name=data['site_name'],
            site_url=data.get('site_url', ''),
            site_username=data['site_username'],
            user_id=current_user.id,
            criticality=data.get('criticality', 'medium'),
            category=data.get('category', 'Logins'),
            is_canary=is_canary,
            canary_fake_pass=canary_fake_pass,
            encryption_type=enc_type,
            client_ciphertext=data.get('client_ciphertext'),
            client_iv=data.get('client_iv'),
            client_salt=data.get('client_salt')
        )

        raw_pass = data.get('password', '')
        if raw_pass and enc_type == 'server_fernet':
            new_item.set_password(raw_pass)
            # Check pwned database in background
            try:
                pwned_c = check_pwned_api(raw_pass)
                new_item.is_pwned = (pwned_c > 0)
                new_item.pwned_count = pwned_c
                new_item.last_pwned_check = datetime.datetime.now(datetime.UTC)
            except Exception:
                pass
        elif enc_type == 'zero_knowledge':
            # Zero-knowledge: password was encrypted client-side; server stores dummy for legacy compatibility
            new_item.set_password(f"[E2EE_ENCRYPTED:{secrets.token_hex(8)}]")

        db.session.add(new_item)
        db.session.commit()
        return jsonify({'message': 'Password saved to Vault!', 'id': new_item.id})

@app.route('/vault/export', methods=['GET'])
@token_required
def export_vault(current_user):
    # Never export honeypots/canaries to prevent user confusion
    items = Vault.query.filter_by(user_id=current_user.id, is_canary=False).all()
    
    if not items:
        return jsonify({'message': 'Vault is empty'}), 400

    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Site Name', 'URL', 'Username', 'Password', 'Criticality', 'Category', 'Encryption'])

    for item in items:
        try:
            password = item.get_password()
        except Exception:
            password = "[Decryption Error]"
        cw.writerow([item.site_name, item.site_url, item.site_username, password, item.criticality, item.category, item.encryption_type])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=vault_export.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/vault/item/<int:item_id>', methods=['GET', 'PUT'])
@token_required
def manage_single_vault_item(current_user, item_id):
    item = Vault.query.get(item_id)
    if not item or item.user_id != current_user.id:
        return jsonify({'message': 'Access Denied'}), 403

    if request.method == 'GET':
        # Canary tripwire check
        if item.is_canary:
            _trigger_canary_tripwire(current_user, item)
            return jsonify({
                'site_name': item.site_name,
                'site_url': item.site_url,
                'site_username': item.site_username,
                'password': item.canary_fake_pass or 'vlt_canary_89fa12',
                'criticality': item.criticality,
                'category': item.category,
                'is_canary': True
            })

        try:
            password = item.get_password()
            return jsonify({
                'site_name': item.site_name,
                'site_url': item.site_url,
                'site_username': item.site_username,
                'password': password,
                'criticality': item.criticality or 'medium',
                'category': item.category or 'Logins',
                'is_pwned': item.is_pwned,
                'pwned_count': item.pwned_count,
                'is_canary': item.is_canary,
                'encryption_type': item.encryption_type,
                'client_ciphertext': item.client_ciphertext,
                'client_iv': item.client_iv,
                'client_salt': item.client_salt
            })
        except Exception:
            return jsonify({'message': 'Decryption Error'}), 500
    
    if request.method == 'PUT':
        data = request.get_json()
        if not data.get('site_name') or not data.get('site_username'):
            return jsonify({'message': 'Required fields are missing'}), 400

        item.site_name = data['site_name']
        item.site_url = data.get('site_url', '')
        item.site_username = data['site_username']
        item.criticality = data.get('criticality', item.criticality or 'medium')
        item.category = data.get('category', item.category or 'Logins')
        
        if data.get('encryption_type') == 'zero_knowledge':
            item.encryption_type = 'zero_knowledge'
            item.client_ciphertext = data.get('client_ciphertext')
            item.client_iv = data.get('client_iv')
            item.client_salt = data.get('client_salt')
        elif data.get('password'):
            item.set_password(data['password'])
            try:
                pwned_c = check_pwned_api(data['password'])
                item.is_pwned = (pwned_c > 0)
                item.pwned_count = pwned_c
                item.last_pwned_check = datetime.datetime.now(datetime.UTC)
            except Exception:
                pass
        
        item.updated_at = datetime.datetime.now(datetime.UTC)
        db.session.commit()
        return jsonify({'message': 'Item updated!'})

def _trigger_canary_tripwire(user, canary_item):
    """Silently logs an intrusion incident and sends a tripwire alert email."""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
    ua = request.headers.get('User-Agent', 'Unknown')[:200]
    try:
        incident = SecurityIncident(
            user_id=user.id,
            incident_type='canary_triggered',
            severity='critical',
            details=f"🚨 Honeypot Tripwire: Canary credential '{canary_item.site_name}' ({canary_item.site_username}) was accessed/decrypted from IP {ip}.",
            ip_address=ip,
            user_agent=ua
        )
        db.session.add(incident)
        db.session.commit()

        if app.config.get('MAIL_USERNAME') and user.email:
            msg = Message(f"🚨 INTRUSION DETECTED: Canary '{canary_item.site_name}' Triggered", sender=app.config['MAIL_USERNAME'], recipients=[user.email])
            msg.body = (
                f"SECURITY TRIPWIRE ALERT\n"
                f"----------------------\n"
                f"A honeypot credential was just accessed in your Vaultary vault!\n\n"
                f"Canary Asset: {canary_item.site_name}\n"
                f"Target Username: {canary_item.site_username}\n"
                f"Detected IP: {ip}\n"
                f"User-Agent: {ua}\n"
                f"Timestamp: {datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
                f"The intruder was served a fake decoy password. Check your Security Center for incident details."
            )
            mail.send(msg)
    except Exception as e:
        print(f"Canary tripwire note: {e}")

@app.route('/vault/decrypt/<int:item_id>', methods=['POST'])
@token_required
def decrypt_vault_item(current_user, item_id):
    item = Vault.query.get(item_id)
    if not item or item.user_id != current_user.id:
        return jsonify({'message': 'Access Denied'}), 403
    
    # Canary Honeypot Tripwire
    if item.is_canary:
        _trigger_canary_tripwire(current_user, item)
        return jsonify({'password': item.canary_fake_pass or 'vlt_sec_canary_8921', 'is_canary': True})

    if item.encryption_type == 'zero_knowledge':
        return jsonify({
            'encryption_type': 'zero_knowledge',
            'client_ciphertext': item.client_ciphertext,
            'client_iv': item.client_iv,
            'client_salt': item.client_salt
        })

    try:
        decrypted = item.get_password()
        return jsonify({'password': decrypted, 'encryption_type': 'server_fernet'})
    except Exception:
        return jsonify({'message': 'Decryption Error'}), 500

@app.route('/vault/delete/<int:item_id>', methods=['DELETE'])
@token_required
def delete_vault_item(current_user, item_id):
    item = Vault.query.get(item_id)
    if not item or item.user_id != current_user.id:
        return jsonify({'message': 'Access Denied'}), 403
    
    db.session.delete(item)
    db.session.commit()
    return jsonify({'message': 'Item deleted'})

# --- CONTEXTUAL WEIGHTED RISK AUDIT ---
@app.route('/vault/security_audit', methods=['GET'])
@token_required
def security_audit(current_user):
    items = Vault.query.filter_by(user_id=current_user.id).all()
    
    if getattr(current_user, 'is_duress', False):
        return jsonify({
            'overall_score': 92,
            'letter_grade': 'A',
            'grade_description': 'Decoy Safe Posture',
            'total_items': 3,
            'critical_count': 0,
            'critical_vulnerable': 0,
            'weak_count': 0,
            'reused_count': 0,
            'breached_count': 0,
            'stale_count': 0,
            'canary_count': 0,
            'blast_radius_clusters': [],
            'remediation_roadmap': []
        })

    real_items = [i for i in items if not i.is_canary]
    canary_items = [i for i in items if i.is_canary]
    total_real = len(real_items)

    if total_real == 0:
        return jsonify({
            'overall_score': 100,
            'letter_grade': 'A+',
            'grade_description': 'Vault Ready / Pristine',
            'total_items': 0,
            'critical_count': 0,
            'critical_vulnerable': 0,
            'weak_count': 0,
            'reused_count': 0,
            'breached_count': 0,
            'stale_count': 0,
            'canary_count': len(canary_items),
            'blast_radius_clusters': [],
            'remediation_roadmap': []
        })

    CRIT_WEIGHTS = {'critical': 3.5, 'high': 2.0, 'medium': 1.0, 'low': 0.5}
    total_weighted_capacity = 0
    earned_strength = 0
    critical_count = 0
    critical_vulnerable = 0
    weak_count = 0
    breached_count = 0
    stale_count = 0
    reused_groups = {}
    remediation_roadmap = []

    now = datetime.datetime.now(datetime.UTC)

    for item in real_items:
        crit = (item.criticality or 'medium').lower()
        if crit == 'critical':
            critical_count += 1

        weight = CRIT_WEIGHTS.get(crit, 1.0)
        total_weighted_capacity += weight * 4.0

        try:
            pw = item.get_password()
        except Exception:
            pw = ""

        if pw:
            analysis = zxcvbn(pw)
            score = analysis.get('score', 0)
        else:
            score = 3 if item.encryption_type == 'zero_knowledge' else 0

        earned_strength += weight * score

        if score < 3:
            weak_count += 1
            if crit in ['critical', 'high']:
                critical_vulnerable += 1
                remediation_roadmap.append({
                    'item_id': item.id,
                    'site_name': item.site_name,
                    'issue_type': 'CRITICAL_WEAK',
                    'title': f'Strengthen Critical Password for {item.site_name}',
                    'description': f'Weak credentials on a {crit.upper()} asset expose high-value data.',
                    'priority': 'CRITICAL',
                    'point_gain': 22 if crit == 'critical' else 14
                })
            else:
                remediation_roadmap.append({
                    'item_id': item.id,
                    'site_name': item.site_name,
                    'issue_type': 'WEAK',
                    'title': f'Upgrade Weak Password for {item.site_name}',
                    'description': 'Entropy is low. Replace with a random 24+ character password.',
                    'priority': 'MEDIUM',
                    'point_gain': 8
                })

        if item.is_pwned:
            breached_count += 1
            remediation_roadmap.append({
                'item_id': item.id,
                'site_name': item.site_name,
                'issue_type': 'BREACHED',
                'title': f'Compromised Credential on {item.site_name}',
                'description': f'Spotted in {item.pwned_count:,} public data breaches (HIBP). Rotate now!',
                'priority': 'URGENT',
                'point_gain': 18
            })

        item_time = item.updated_at or item.created_at
        if item_time:
            if item_time.tzinfo is None:
                item_time = item_time.replace(tzinfo=datetime.timezone.utc)
            days_old = max(0, (now - item_time).days)
            if days_old > 90:
                stale_count += 1
                if days_old > 180:
                    remediation_roadmap.append({
                        'item_id': item.id,
                        'site_name': item.site_name,
                        'issue_type': 'STALE',
                        'title': f'Rotate Stale Password for {item.site_name}',
                        'description': f'Password unchanged for {days_old} days.',
                        'priority': 'LOW',
                        'point_gain': 6
                    })

        if pw:
            reused_groups.setdefault(pw, []).append(item)

    blast_radius_clusters = []
    reuse_penalty = 0
    for pw, cluster in reused_groups.items():
        if len(cluster) > 1:
            has_crit = any((x.criticality or 'medium').lower() in ['critical', 'high'] for x in cluster)
            is_cross_tier = has_crit and any((x.criticality or 'medium').lower() in ['low', 'medium'] for x in cluster)
            severity = 'CRITICAL' if is_cross_tier else ('HIGH' if has_crit else 'MODERATE')
            penalty = 18 if is_cross_tier else (12 if has_crit else 6)
            reuse_penalty += penalty
            
            site_names = [x.site_name for x in cluster]
            blast_radius_clusters.append({
                'count': len(cluster),
                'sites': site_names,
                'severity': severity,
                'is_cross_tier': is_cross_tier
            })

            remediation_roadmap.append({
                'item_id': cluster[0].id,
                'site_name': ', '.join(site_names[:2]),
                'issue_type': 'REUSE',
                'title': f'Break Password Reuse Cluster ({len(cluster)} accounts)',
                'description': f'Identical password shared across {", ".join(site_names)}.{" High risk: crosses critical and low tiers!" if is_cross_tier else ""}',
                'priority': 'URGENT' if is_cross_tier else 'HIGH',
                'point_gain': 16 if is_cross_tier else 10
            })

    base_score = (earned_strength / total_weighted_capacity) * 100 if total_weighted_capacity > 0 else 100
    breach_penalty = min(30, breached_count * 15)
    stale_penalty = min(15, stale_count * 4)
    overall_score = max(0, min(100, round(base_score - (reuse_penalty * 0.45) - breach_penalty - stale_penalty)))

    if overall_score >= 90:
        letter_grade = 'A+'
        grade_desc = 'Hardened Security Posture'
    elif overall_score >= 80:
        letter_grade = 'A'
        grade_desc = 'Robust Security'
    elif overall_score >= 70:
        letter_grade = 'B'
        grade_desc = 'Good Posture (Minor Gaps)'
    elif overall_score >= 60:
        letter_grade = 'C'
        grade_desc = 'Moderate Risk (Action Recommended)'
    elif overall_score >= 40:
        letter_grade = 'D'
        grade_desc = 'Vulnerable (Elevated Threat)'
    else:
        letter_grade = 'F'
        grade_desc = 'Critical Vulnerability (Immediate Action Needed)'

    remediation_roadmap.sort(key=lambda x: x['point_gain'], reverse=True)

    return jsonify({
        'overall_score': overall_score,
        'letter_grade': letter_grade,
        'grade_description': grade_desc,
        'total_items': total_real,
        'critical_count': critical_count,
        'critical_vulnerable': critical_vulnerable,
        'weak_count': weak_count,
        'reused_count': sum(len(c['sites']) for c in blast_radius_clusters),
        'breached_count': breached_count,
        'stale_count': stale_count,
        'canary_count': len(canary_items),
        'blast_radius_clusters': blast_radius_clusters,
        'remediation_roadmap': remediation_roadmap[:6]
    })

# --- HAVEIBEENPWNED K-ANONYMITY BATCH SCAN ---
@app.route('/vault/scan_all_breaches', methods=['POST'])
@limiter.limit("5 per minute")
@token_required
def scan_all_breaches(current_user):
    items = Vault.query.filter_by(user_id=current_user.id, is_canary=False).all()
    scanned = 0
    breached = 0

    for item in items:
        try:
            pw = item.get_password()
            if pw and item.encryption_type != 'zero_knowledge':
                c = check_pwned_api(pw)
                item.is_pwned = (c > 0)
                item.pwned_count = c
                item.last_pwned_check = datetime.datetime.now(datetime.UTC)
                scanned += 1
                if c > 0:
                    breached += 1
        except Exception:
            pass

    db.session.commit()
    return jsonify({
        'total_scanned': scanned,
        'breached_found': breached,
        'message': f"Scan complete: {breached} breached passwords detected out of {scanned} checked."
    })

# --- CANARY HONEYPOT DEPLOYMENT ---
@app.route('/vault/deploy_canary', methods=['POST'])
@token_required
def deploy_canary(current_user):
    data = request.get_json() or {}
    lure_type = data.get('lure_type', 'aws')

    PRESETS = {
        'aws': {
            'site_name': 'AWS Root Production Console',
            'site_url': 'https://signin.aws.amazon.com/console',
            'site_username': f'root_admin_{secrets.token_hex(3)}@corporate-cloud.internal',
            'category': 'Cloud Infrastructure',
            'fake_pass': f'AKIA{secrets.token_hex(8).upper()}'
        },
        'vpn': {
            'site_name': 'Corporate VPN Gateway (Fortinet)',
            'site_url': 'https://vpn.corp-secure-gateway.internal',
            'site_username': f'admin_secops_{secrets.token_hex(2)}',
            'category': 'Work',
            'fake_pass': f'VPN#Sec_{secrets.token_hex(6)}!99'
        },
        'stripe': {
            'site_name': 'Stripe Production API Gateway',
            'site_url': 'https://dashboard.stripe.com/apikeys',
            'site_username': 'live_secret_key_holder',
            'category': 'Financial',
            'fake_pass': f'sk_live_{secrets.token_hex(16)}'
        },
        'crypto': {
            'site_name': 'Binance Institutional Custody',
            'site_url': 'https://binance.com/custody',
            'site_username': f'cold_vault_{secrets.token_hex(4)}@secops.internal',
            'category': 'Financial',
            'fake_pass': f'Bnc#Cold_{secrets.token_hex(8)}'
        }
    }

    preset = PRESETS.get(lure_type, PRESETS['aws'])

    canary = Vault(
        site_name=data.get('site_name') or preset['site_name'],
        site_url=data.get('site_url') or preset['site_url'],
        site_username=data.get('site_username') or preset['site_username'],
        user_id=current_user.id,
        criticality='critical',
        category=data.get('category') or preset['category'],
        is_canary=True,
        canary_fake_pass=preset['fake_pass'],
        encryption_type='server_fernet'
    )
    canary.set_password(preset['fake_pass'])

    db.session.add(canary)
    db.session.commit()
    return jsonify({'message': f"Canary lure '{canary.site_name}' successfully armed and deployed!", 'id': canary.id})

# --- SECURITY INCIDENTS FEED ---
@app.route('/security/incidents', methods=['GET'])
@token_required
def get_incidents(current_user):
    incidents = SecurityIncident.query.filter_by(user_id=current_user.id).order_by(SecurityIncident.timestamp.desc()).limit(20).all()
    return jsonify([{
        'id': inc.id,
        'incident_type': inc.incident_type,
        'severity': inc.severity,
        'details': inc.details,
        'ip_address': inc.ip_address,
        'user_agent': inc.user_agent,
        'timestamp': inc.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if inc.timestamp else None,
        'is_acknowledged': inc.is_acknowledged
    } for inc in incidents])

@app.route('/security/incidents/<int:incident_id>/ack', methods=['POST'])
@token_required
def acknowledge_incident(current_user, incident_id):
    inc = SecurityIncident.query.get(incident_id)
    if not inc or inc.user_id != current_user.id:
        return jsonify({'message': 'Access Denied'}), 403
    inc.is_acknowledged = True
    db.session.commit()
    return jsonify({'message': 'Incident marked as acknowledged'})

# --- DURESS / PANIC PIN CONFIGURATION ---
@app.route('/profile/duress_pin', methods=['POST'])
@token_required
def set_duress_pin(current_user):
    data = request.get_json() or {}
    pin = str(data.get('pin', '')).strip()
    
    if not pin:
        current_user.duress_pin_hash = None
        db.session.commit()
        return jsonify({'message': 'Duress PIN disabled.'})
        
    if not re.match(r'^\d{4,8}$', pin):
        return jsonify({'message': 'Duress PIN must be 4 to 8 digits.'}), 400

    current_user.duress_pin_hash = bcrypt.generate_password_hash(pin).decode('utf-8')
    db.session.commit()
    return jsonify({'message': 'Duress / Panic PIN successfully armed!'})

# --- SECURE NOTES ROUTES ---
@app.route('/notes', methods=['GET'])
@token_required
def get_notes(current_user):
    items = SecureNote.query.filter_by(user_id=current_user.id).all()
    output = []
    for item in items:
        output.append({
            'id': item.id,
            'title': item.title,
            'content': item.content,
            'created_at': item.created_at,
            'updated_at': item.updated_at
        })
    return jsonify(output)

@app.route('/notes', methods=['POST'])
@token_required
def add_note(current_user):
    data = request.get_json()
    if not data.get('title') or not data.get('content'):
        return jsonify({'message': 'Required fields are missing'}), 400

    new_note = SecureNote(user_id=current_user.id, title=data['title'])
    new_note.set_content(data['content'])
    
    db.session.add(new_note)
    db.session.commit()
    return jsonify({'message': 'Note saved!'}), 201

@app.route('/notes/<int:note_id>', methods=['PUT'])
@token_required
def update_note(current_user, note_id):
    data = request.get_json()
    note = SecureNote.query.get(note_id)
    if not note or note.user_id != current_user.id:
        return jsonify({'message': 'Access Denied'}), 403

    if not data.get('title') or not data.get('content'):
        return jsonify({'message': 'Required fields are missing'}), 400

    note.title = data['title']
    note.set_content(data['content'])
    
    db.session.commit()
    return jsonify({'message': 'Note updated!'})

@app.route('/notes/<int:note_id>', methods=['DELETE'])
@token_required
def delete_note(current_user, note_id):
    note = SecureNote.query.get(note_id)
    if not note or note.user_id != current_user.id:
        return jsonify({'message': 'Access Denied'}), 403

    db.session.delete(note)
    db.session.commit()
    return jsonify({'message': 'Note deleted'})

@app.route('/notes/decrypt/<int:note_id>', methods=['POST'])
@token_required
def decrypt_note(current_user, note_id):
    note = SecureNote.query.get(note_id)
    if not note or note.user_id != current_user.id:
        return jsonify({'message': 'Access Denied'}), 403
    
    try:
        decrypted_title = note.title
        decrypted_content = note.get_content()
        return jsonify({
            'status': 'success',
            'decrypted_title': decrypted_title,
            'decrypted_content': decrypted_content
        })
    except:
        return jsonify({'message': 'Decryption Error'}), 500

@app.route('/admin/users', methods=['GET'])
@token_required
@admin_required
def get_all_users(current_user):
    users = User.query.all()
    output = [{'id': u.id, 'username': u.username, 'email': u.email, 'auth_provider': u.auth_provider, 'is_admin': u.is_admin} for u in users]
    return jsonify(output)

@app.route('/admin/delete/<int:user_id>', methods=['DELETE'])
@token_required
@admin_required
def admin_delete_user(current_user, user_id):
    user_to_delete = User.query.get(user_id)
    if not user_to_delete: return jsonify({'message': 'Not found'}), 404
    if user_to_delete.id == current_user.id: return jsonify({'message': 'Cannot delete self'}), 400
    db.session.delete(user_to_delete)
    db.session.commit()
    return jsonify({'message': 'Deleted'})

def check_pwned_api(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1password[:5], sha1password[5:]
    try:
        res = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
        if res.status_code != 200: return 0 
        for line in res.text.splitlines():
            h, count = line.split(':')
            if h == suffix: return int(count)
        return 0
    except: return 0 

@app.route('/check_password', methods=['POST'])
def check_password():
    data = request.get_json()
    password = data.get('password', '')
    if not password: return jsonify({'error': 'No password'}), 400
    results = zxcvbn(password)
    breach_count = check_pwned_api(password)
    token = request.cookies.get('token')
    if token:
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if not decoded.get('2fa_pending'):
                db.session.add(History(password_score=results['score'], user_id=decoded['user_id']))
                db.session.commit()
        except: pass
    return jsonify({'score': results['score'], 'crack_time': results['crack_times_display']['offline_slow_hashing_1e4_per_second'], 'feedback': results['feedback'], 'breach_count': breach_count, 'guesses': results['guesses'], 'sequence': results['sequence'], 'password_length': len(password)})

@app.route('/history', methods=['GET'])
@token_required
def get_history(current_user):
    records = History.query.filter_by(user_id=current_user.id).order_by(History.checked_on.desc()).limit(10).all()
    return jsonify([{'score': h.password_score, 'date': h.checked_on.strftime('%Y-%m-%d %H:%M')} for h in records])

@app.route('/generate_password', methods=['GET'])
def generate_password():
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(24))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password) and any(c in "!@#$%^&*" for c in password)): break
    return jsonify({'password': password})

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Ping database to prevent Supabase from pausing
        User.query.first()
        return jsonify({"status": "ok", "db": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/robots.txt')
def robots(): return send_from_directory('static', 'robots.txt')

@app.route('/sitemap.xml')
def sitemap(): return send_from_directory('static', 'sitemap.xml')

@app.route('/contact', methods=['POST'])
@limiter.limit("3 per minute")
def contact_support():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    message = data.get('message')
    
    if not name or not email or not message or not app.config['MAIL_USERNAME']:
        return jsonify({'message': 'All fields are required'}), 400
        
    try:
        msg = Message(f'Support Request: {name}', sender=app.config['MAIL_USERNAME'], recipients=[app.config['MAIL_USERNAME']])
        msg.body = f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}"
        msg.reply_to = email
        mail.send(msg)
        return jsonify({'message': 'Message sent successfully!'})
    except Exception as e:
        return jsonify({'message': 'Error sending message'}), 500

def upgrade_database_schema():
    """Safely upgrades database schema with newly introduced columns and tables."""
    from sqlalchemy import inspect, text
    try:
        db.create_all()
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Upgrade vault table
        if 'vault' in tables:
            vault_cols = [c['name'] for c in inspector.get_columns('vault')]
            vault_migrations = [
                ('criticality', "VARCHAR(20) DEFAULT 'medium'"),
                ('category', "VARCHAR(50) DEFAULT 'Logins'"),
                ('is_pwned', "BOOLEAN DEFAULT FALSE"),
                ('pwned_count', "INTEGER DEFAULT 0"),
                ('last_pwned_check', "TIMESTAMP"),
                ('is_canary', "BOOLEAN DEFAULT FALSE"),
                ('canary_fake_pass', "VARCHAR(100)"),
                ('encryption_type', "VARCHAR(30) DEFAULT 'server_fernet'"),
                ('client_ciphertext', "TEXT"),
                ('client_iv', "VARCHAR(64)"),
                ('client_salt', "VARCHAR(64)"),
                ('created_at', "TIMESTAMP"),
                ('updated_at', "TIMESTAMP"),
            ]
            with db.engine.connect() as conn:
                for col_name, col_def in vault_migrations:
                    if col_name not in vault_cols:
                        try:
                            conn.execute(text(f"ALTER TABLE vault ADD COLUMN {col_name} {col_def}"))
                        except Exception:
                            pass
                conn.commit()

        # Upgrade user table
        user_table = 'user' if 'user' in tables else ('users' if 'users' in tables else None)
        if user_table:
            user_cols = [c['name'] for c in inspector.get_columns(user_table)]
            user_migrations = [
                ('duress_pin_hash', "VARCHAR(128)"),
                ('vault_key_salt', "VARCHAR(64)"),
            ]
            with db.engine.connect() as conn:
                for col_name, col_def in user_migrations:
                    if col_name not in user_cols:
                        try:
                            conn.execute(text(f'ALTER TABLE "{user_table}" ADD COLUMN {col_name} {col_def}'))
                        except Exception:
                            try:
                                conn.execute(text(f"ALTER TABLE {user_table} ADD COLUMN {col_name} {col_def}"))
                            except Exception:
                                pass
                conn.commit()
    except Exception as e:
        print(f"Schema upgrade note: {e}")

# --- DATABASE TABLE CREATION & MIGRATION ---
# Serverless environments (Vercel) must never execute heavy DDL migrations during cold-start invocation
if not IS_SERVERLESS:
    with app.app_context():
        try:
            upgrade_database_schema()
        except Exception as e:
            print(f"DB Migration skipped: {e}", flush=True)
else:
    # On serverless (Vercel), if running on ephemeral SQLite without DATABASE_URL, create tables in /tmp
    if not uri:
        with app.app_context():
            try:
                db.create_all()
            except Exception as e:
                print(f"Serverless DB init note: {e}", flush=True)

print(f"[VAULTARY] Module import completed! Mode={'Serverless' if IS_SERVERLESS else 'Local'}, DB={app.config.get('SQLALCHEMY_DATABASE_URI')}", flush=True)

if __name__ == '__main__':
    app.run(debug=True)