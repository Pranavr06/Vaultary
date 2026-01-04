import os
import hashlib
import requests
import secrets
import string
import jwt
import datetime
import urllib.parse
import pyotp
import qrcode
import io
import base64
import re
from flask import Flask, render_template, request, jsonify, make_response, url_for, redirect, session, send_from_directory
from zxcvbn import zxcvbn
from flask_sqlalchemy import SQLAlchemy
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

load_dotenv()

app = Flask(__name__)

# --- PASTE THIS BLOCK RIGHT HERE ---
linkedin_secret = os.getenv('LINKEDIN_CLIENT_SECRET')
if linkedin_secret:
    print(f"✅ DEBUG: LinkedIn Secret FOUND. Length: {len(linkedin_secret)}")
else:
    print("❌ DEBUG: LinkedIn Secret is TOTALLY MISSING in this environment.")
# ------------------------------------

# --- FIX HTTPS ON RENDER ---
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

CORS(app)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Handle Supabase/Postgres URL fix (postgres:// -> postgresql://)
uri = os.getenv('DATABASE_URL')
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- SECURITY CONFIG ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
    'style-src': ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
    'font-src': ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com"],
    'img-src': ["'self'", "data:", "ui-avatars.com", "*.googleusercontent.com", "*.githubusercontent.com", "*.licdn.com", "media.licdn.com"]
}
talisman = Talisman(app, force_https=False, content_security_policy=csp)

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

db = SQLAlchemy(app)
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
    two_factor_secret = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    
    # Relationships
    history = db.relationship('History', backref='owner', lazy=True, cascade="all, delete-orphan")
    vault_items = db.relationship('Vault', backref='owner', lazy=True, cascade="all, delete-orphan")

class Vault(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(100), nullable=False)
    site_url = db.Column(db.String(200), nullable=True)
    site_username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.LargeBinary, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def get_encryption_key():
        key = os.getenv('VAULT_KEY') or os.getenv('ENCRYPTION_KEY')
        if not key:
            raise ValueError("No Encryption Key Found in Environment Variables")
        return key.encode() 

    def set_password(self, plaintext):
        f = Fernet(Vault.get_encryption_key())
        self.encrypted_password = f.encrypt(plaintext.encode())

    def get_password(self):
        f = Fernet(Vault.get_encryption_key())
        return f.decrypt(self.encrypted_password).decode()

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    password_score = db.Column(db.Integer, nullable=False)
    checked_on = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token: return jsonify({'message': 'Missing Token'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if data.get('2fa_pending'): return jsonify({'message': '2FA Verification Required'}), 403
            current_user = User.query.filter_by(id=data['user_id']).first()
        except: return jsonify({'message': 'Invalid Token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if not current_user.is_admin: return jsonify({'message': 'Admin access required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/')
def home(): return render_template('index.html')

# --- CUSTOM ERROR HANDLER FOR RATE LIMIT ---
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"message": "Too many attempts. Please wait 1 minute."}), 429

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
            token = jwt.encode({'email': new_user.email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'])
            verify_url = url_for('verify_email', token=token, _external=True)
            msg = Message('Verify Your PassGuard Account', sender=app.config['MAIL_USERNAME'], recipients=[new_user.email])
            msg.body = f'Welcome to PassGuard! Please click this link to verify your email: {verify_url}'
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
    
    if user and bcrypt.check_password_hash(user.password, data['password']):
        # --- BLOCK LOGIN IF NOT VERIFIED ---
        if not user.is_verified:
            return jsonify({'message': 'Please verify your email first! Check your inbox.'}), 401

        if user.is_2fa_enabled:
            temp_token = jwt.encode({'user_id': user.id, '2fa_pending': True, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}, app.config['SECRET_KEY'])
            return jsonify({'status': '2fa_required', 'temp_token': temp_token})
            
        token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'])
        resp = make_response(jsonify({'status': 'success', 'message': 'Login successful', 'token': token, 'is_admin': user.is_admin}))
        resp.set_cookie('token', token, httponly=True)
        return resp
        
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/login/verify_2fa', methods=['POST'])
@limiter.limit("3 per minute")
def login_verify_2fa():
    data = request.get_json()
    try:
        decoded = jwt.decode(data.get('temp_token'), app.config['SECRET_KEY'], algorithms=["HS256"])
        if not decoded.get('2fa_pending'): return jsonify({'message': 'Invalid flow'}), 400
        user = User.query.get(decoded['user_id'])
        if not user: return jsonify({'message': 'User not found'}), 404
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(data.get('code')):
            token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'])
            resp = make_response(jsonify({'status': 'success', 'token': token, 'username': user.username, 'is_admin': user.is_admin}))
            resp.set_cookie('token', token, httponly=True)
            return resp
        else: return jsonify({'message': 'Invalid Code'}), 400
    except: return jsonify({'message': 'Session expired'}), 401

@app.route('/2fa/setup', methods=['POST'])
@token_required
def setup_2fa(current_user):
    secret = pyotp.random_base32()
    current_user.two_factor_secret = secret
    db.session.commit()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="PassGuard")
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
    if totp.verify(data.get('code')):
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
    if not user: return jsonify({'message': 'Link sent if exists.'})
    
    # --- ONE-TIME USE TRICK: Sign with current password hash ---
    dynamic_secret = app.config['SECRET_KEY'] + user.password
    token = jwt.encode(
        {'reset_email': user.email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)}, 
        dynamic_secret
    )
    
    link = f"http://127.0.0.1:5000/?reset_token={token}"
    try:
        msg = Message('Password Reset', sender=app.config['MAIL_USERNAME'], recipients=[user.email])
        msg.body = f"Reset link (Valid for 10 mins): {link}"
        mail.send(msg)
    except: return jsonify({'message': 'Error sending email'}), 500
    return jsonify({'message': 'Link sent if exists.'})

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
        
        dummy = bcrypt.generate_password_hash(secrets.token_urlsafe(16)).decode('utf-8')
        user = User(
            username=user_info['name'], 
            email=user_info['email'], 
            password=dummy, 
            is_verified=True, 
            auth_provider='google', 
            profile_pic=user_info['picture'],
            is_admin=is_first_user # Set Admin if first user
        )
        db.session.add(user)
        db.session.commit()
    token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'])
    resp = make_response(redirect('/'))
    resp.set_cookie('token', token, httponly=True)
    resp.set_cookie('social_login_user', user.username, max_age=10)
    resp.set_cookie('social_login_admin', str(user.is_admin).lower(), max_age=10)
    return resp

@app.route('/login/github')
def github_login():
    return github.authorize_redirect(url_for('github_callback', _external=True))

@app.route('/login/github/callback')
def github_callback():
    token = github.authorize_access_token()
    resp = github.get('user').json()
    email = resp.get('email') or f"{resp['login']}@github.com"
    
    user = User.query.filter_by(email=email).first()
    if not user:
        # --- CHECK IF THIS IS THE FIRST USER ---
        is_first_user = User.query.first() is None
        
        dummy = bcrypt.generate_password_hash(secrets.token_urlsafe(16)).decode('utf-8')
        user = User(
            username=resp['login'], 
            email=email, 
            password=dummy, 
            is_verified=True, 
            auth_provider='github', 
            profile_pic=resp['avatar_url'],
            is_admin=is_first_user # Set Admin if first user
        )
        db.session.add(user)
        db.session.commit()
    
    jwt_token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'])
    response = make_response(redirect('/'))
    response.set_cookie('token', jwt_token, httponly=True)
    response.set_cookie('social_login_user', user.username, max_age=10)
    response.set_cookie('social_login_admin', str(user.is_admin).lower(), max_age=10)
    return response

@app.route('/login/linkedin')
def linkedin_login():
    # --- FORCE HTTPS SCHEME HERE ---
    return linkedin.authorize_redirect(url_for('linkedin_callback', _external=True, _scheme='https'))

@app.route('/login/linkedin/callback')
def linkedin_callback():
    token = linkedin.authorize_access_token()
    user_info = linkedin.userinfo()
    
    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        # --- CHECK IF THIS IS THE FIRST USER ---
        is_first_user = User.query.first() is None
        
        dummy = bcrypt.generate_password_hash(secrets.token_urlsafe(16)).decode('utf-8')
        user = User(
            username=user_info['name'], 
            email=user_info['email'], 
            password=dummy, 
            is_verified=True, 
            auth_provider='linkedin', 
            profile_pic=user_info.get('picture', ''),
            is_admin=is_first_user # Set Admin if first user
        )
        db.session.add(user)
        db.session.commit()
        
    jwt_token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'])
    response = make_response(redirect('/'))
    response.set_cookie('token', jwt_token, httponly=True)
    response.set_cookie('social_login_user', user.username, max_age=10)
    response.set_cookie('social_login_admin', str(user.is_admin).lower(), max_age=10)
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
        return jsonify({'username': current_user.username, 'email': current_user.email, 'phone': current_user.phone, 'dob': current_user.dob, 'profile_pic': current_user.profile_pic, 'is_admin': current_user.is_admin, 'is_2fa_enabled': current_user.is_2fa_enabled})
    if request.method == 'PUT':
        data = request.get_json()
        current_user.email = data.get('email', current_user.email)
        
        phone = data.get('phone', current_user.phone)
        dob = data.get('dob', current_user.dob)

        if phone and not re.match(r'^\d{10}$', phone):
            return jsonify({'message': 'Phone number must be exactly 10 digits.'}), 400
            
        if dob:
            try:
                day, month, year = map(int, dob.split('/'))
                birth_date = datetime.date(year, month, day)
                today = datetime.date.today()
                age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
                if birth_date > today: return jsonify({'message': 'Date cannot be in future.'}), 400
                if age < 13: return jsonify({'message': 'You must be at least 13 years old.'}), 400
                if age > 120: return jsonify({'message': 'Invalid age.'}), 400
            except ValueError:
                return jsonify({'message': 'Invalid Date format.'}), 400

        current_user.phone = phone
        current_user.dob = dob
        db.session.commit()
        return jsonify({'message': 'Updated'})
    if request.method == 'DELETE':
        db.session.delete(current_user)
        db.session.commit()
        resp = make_response(jsonify({'message': 'Deleted'}))
        resp.set_cookie('token', '', expires=0)
        return resp

# --- VAULT ROUTES ---
@app.route('/vault', methods=['GET', 'POST'])
@token_required
def manage_vault(current_user):
    if request.method == 'GET':
        items = Vault.query.filter_by(user_id=current_user.id).all()
        output = []
        for item in items:
            output.append({
                'id': item.id,
                'site_name': item.site_name,
                'site_url': item.site_url,
                'site_username': item.site_username
            })
        return jsonify(output)

    if request.method == 'POST':
        data = request.get_json()
        new_item = Vault(
            site_name=data['site_name'],
            site_url=data.get('site_url', ''),
            site_username=data['site_username'],
            user_id=current_user.id
        )
        new_item.set_password(data['password'])
        db.session.add(new_item)
        db.session.commit()
        return jsonify({'message': 'Password saved to Vault!'})

@app.route('/vault/decrypt/<int:item_id>', methods=['POST'])
@token_required
def decrypt_vault_item(current_user, item_id):
    item = Vault.query.get(item_id)
    if not item or item.user_id != current_user.id:
        return jsonify({'message': 'Access Denied'}), 403
    
    try:
        decrypted = item.get_password()
        return jsonify({'password': decrypted})
    except:
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
        password = ''.join(secrets.choice(alphabet) for i in range(16))
        if (any(c.islower() for c in password) and any(c.isupper() for c in password) and any(c.isdigit() for c in password) and any(c in "!@#$%^&*" for c in password)): break
    return jsonify({'password': password})

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
    
    if not name or not email or not message:
        return jsonify({'message': 'All fields are required'}), 400
        
    try:
        msg = Message(f'Support Request: {name}', sender=app.config['MAIL_USERNAME'], recipients=[app.config['MAIL_USERNAME']])
        msg.body = f"Name: {name}\nEmail: {email}\n\nMessage:\n{message}"
        msg.reply_to = email
        mail.send(msg)
        return jsonify({'message': 'Message sent successfully!'})
    except Exception as e:
        return jsonify({'message': 'Error sending message'}), 500

# --- DATABASE TABLE CREATION (FIXED FOR RENDER) ---
# We move this OUTSIDE the "if __name__" block so Render runs it
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)