import os
import re
import shutil
import uuid
import time
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional
from urllib.parse import urlencode

import requests  # type: ignore
from logging.handlers import RotatingFileHandler
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(BASE_DIR, 'static', 'uploads')
LISTING_UPLOAD_DIR = os.path.join(UPLOAD_ROOT, 'listings')
BEFORE_AFTER_UPLOAD_DIR = os.path.join(UPLOAD_ROOT, 'before_after')
QUOTE_UPLOAD_DIR = os.path.join(UPLOAD_ROOT, 'quotes')
QUOTE_UPLOAD_WITH_FILE_DIR = os.path.join(QUOTE_UPLOAD_DIR, 'with_file')
QUOTE_UPLOAD_REFERENCE_DIR = os.path.join(QUOTE_UPLOAD_DIR, 'reference')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'stl', '3mf'}

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = os.environ.get('DRIVENBYFAITH3D_SECRET', 'change-this-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB upload limit
app.config['MS_GRAPH_CLIENT_ID'] = os.environ.get('MS_GRAPH_CLIENT_ID')
app.config['MS_GRAPH_CLIENT_SECRET'] = os.environ.get('MS_GRAPH_CLIENT_SECRET')
app.config['MS_GRAPH_TENANT'] = os.environ.get('MS_GRAPH_TENANT', 'common')
app.config['MS_GRAPH_REDIRECT_URI'] = os.environ.get('MS_GRAPH_REDIRECT_URI', 'http://localhost:5000/oauth/callback')
app.config['MS_GRAPH_SCOPES'] = os.environ.get('MS_GRAPH_SCOPES', 'https://graph.microsoft.com/Mail.Send offline_access')

# Configure logging to a file
if not app.debug:
    file_handler = RotatingFileHandler('flask_app.log', maxBytes=1024 * 1024 * 10, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO) # Set app logger level to INFO

# Ensure upload directories exist
os.makedirs(LISTING_UPLOAD_DIR, exist_ok=True)
os.makedirs(BEFORE_AFTER_UPLOAD_DIR, exist_ok=True)
os.makedirs(QUOTE_UPLOAD_WITH_FILE_DIR, exist_ok=True)
os.makedirs(QUOTE_UPLOAD_REFERENCE_DIR, exist_ok=True)

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    quotes = db.relationship('QuoteRequest', backref='user', lazy=True)
    messages_sent = db.relationship('QuoteMessage', back_populates='sender', lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Listing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class BeforeAfter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    stl_filename = db.Column(db.String(255))
    printed_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class QuoteRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requester_name = db.Column(db.String(120), nullable=False)
    request_type = db.Column(db.String(40), nullable=False)  # "has_file" or "needs_design"
    uploaded_filename = db.Column(db.String(255))
    reference_image_filename = db.Column(db.String(255))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    deleted_at = db.Column(db.DateTime)
    messages = db.relationship('QuoteMessage', backref='quote', lazy=True, cascade='all, delete-orphan')


class QuoteMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quote_id = db.Column(db.Integer, db.ForeignKey('quote_request.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_admin = db.Column(db.Boolean, default=True)
    subject = db.Column(db.String(200))
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', back_populates='messages_sent', lazy=True)


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def save_uploaded_file(file_storage, subdirectory: str) -> Optional[str]:
    if not file_storage or file_storage.filename == '':
        return None

    if not allowed_file(file_storage.filename):
        flash('Invalid file type. Allowed types: png, jpg, jpeg, gif.', 'error')
        return None

    filename = secure_filename(file_storage.filename)
    unique_name = f"{uuid.uuid4().hex}_{filename}"

    target_dir = os.path.join(UPLOAD_ROOT, subdirectory)
    os.makedirs(target_dir, exist_ok=True)

    file_path = os.path.join(target_dir, unique_name)
    file_storage.save(file_path)

    relative_path = os.path.join('uploads', subdirectory, unique_name)
    return relative_path.replace('\\', '/')


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)

    return wrapper


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get('user_id') or not session.get('is_admin'):
            flash('Administrator access required.', 'error')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)

    return wrapper


def get_current_user() -> Optional[User]:
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.session.get(User, user_id)


def is_valid_email(value: str) -> bool:
    if not value:
        return False

    email_pattern = r'^[^@\s]+@[^@\s]+\.[^@\s]+$'
    return bool(re.match(email_pattern, value))


def graph_authority_url() -> str:
    tenant = app.config.get('MS_GRAPH_TENANT') or 'common'
    return f"https://login.microsoftonline.com/{tenant}"


def store_graph_tokens(token_data: dict) -> None:
    access_token = token_data.get('access_token')
    if access_token:
        session['graph_access_token'] = access_token
    expires_in = int(token_data.get('expires_in', 3599) or 3599)
    session['graph_token_expires_at'] = time.time() + expires_in
    refresh_token = token_data.get('refresh_token')
    if refresh_token:
        session['graph_refresh_token'] = refresh_token


def clear_graph_tokens() -> None:
    session.pop('graph_access_token', None)
    session.pop('graph_refresh_token', None)
    session.pop('graph_token_expires_at', None)
    session.pop('graph_oauth_state', None)


def build_graph_authorization_url(state: str) -> Optional[str]:
    client_id = app.config.get('MS_GRAPH_CLIENT_ID')
    redirect_uri = app.config.get('MS_GRAPH_REDIRECT_URI')
    scopes = app.config.get('MS_GRAPH_SCOPES')

    if not client_id or not redirect_uri or not scopes:
        return None

    params = {
        'client_id': client_id,
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'response_mode': 'query',
        'scope': scopes,
        'state': state,
        'prompt': 'select_account',
    }
    return f"{graph_authority_url()}/oauth2/v2.0/authorize?{urlencode(params)}"


def exchange_code_for_token(code: str) -> Optional[dict]:
    client_id = app.config.get('MS_GRAPH_CLIENT_ID')
    client_secret = app.config.get('MS_GRAPH_CLIENT_SECRET')
    redirect_uri = app.config.get('MS_GRAPH_REDIRECT_URI')
    scopes = app.config.get('MS_GRAPH_SCOPES')

    if not client_id or not client_secret or not redirect_uri:
        return None

    data = {
        'client_id': client_id,
        'scope': scopes,
        'code': code,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
        'client_secret': client_secret,
    }

    token_url = f"{graph_authority_url()}/oauth2/v2.0/token"
    try:
        response = requests.post(token_url, data=data, timeout=10)
    except requests.RequestException as exc:
        app.logger.error('Microsoft Graph token exchange failed: %s', exc)
        return None

    if response.ok:
        return response.json()

    app.logger.error('Microsoft Graph token exchange failed: %s', response.text)
    return None


def get_graph_access_token() -> Optional[str]:
    client_id = app.config.get('MS_GRAPH_CLIENT_ID')
    client_secret = app.config.get('MS_GRAPH_CLIENT_SECRET')
    redirect_uri = app.config.get('MS_GRAPH_REDIRECT_URI')
    scopes = app.config.get('MS_GRAPH_SCOPES')

    if not client_id or not client_secret or not redirect_uri:
        return None

    access_token = session.get('graph_access_token')
    expires_at = session.get('graph_token_expires_at', 0)
    if access_token and expires_at - 60 > time.time():
        return access_token

    refresh_token = session.get('graph_refresh_token')
    if not refresh_token:
        return None

    data = {
        'client_id': client_id,
        'scope': scopes,
        'refresh_token': refresh_token,
        'redirect_uri': redirect_uri,
        'grant_type': 'refresh_token',
        'client_secret': client_secret,
    }

    token_url = f"{graph_authority_url()}/oauth2/v2.0/token"
    try:
        response = requests.post(token_url, data=data, timeout=10)
    except requests.RequestException as exc:
        app.logger.error('Failed to refresh Microsoft Graph token: %s', exc)
        return None

    if response.ok:
        token_data = response.json()
        store_graph_tokens(token_data)
        return token_data.get('access_token')

    app.logger.error('Failed to refresh Microsoft Graph token: %s', response.text)
    clear_graph_tokens()
    return None


def is_graph_connected() -> bool:
    expires_at = session.get('graph_token_expires_at', 0)
    if session.get('graph_access_token') and expires_at - 60 > time.time():
        return True
    if session.get('graph_refresh_token'):
        return bool(get_graph_access_token())
    return False


def send_email(to_address: str, subject: str, body: str) -> bool:
    access_token = get_graph_access_token()
    if not access_token:
        app.logger.warning('Microsoft Graph not connected; unable to send email to %s', to_address)
        return False

    payload = {
        'message': {
            'subject': subject,
            'body': {
                'contentType': 'Text',
                'content': body,
            },
            'toRecipients': [
                {'emailAddress': {'address': to_address}}
            ],
        },
        'saveToSentItems': True,
    }

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }

    try:
        response = requests.post(
            'https://graph.microsoft.com/v1.0/me/sendMail',
            json=payload,
            headers=headers,
            timeout=10,
        )
    except requests.RequestException as exc:
        app.logger.error('Microsoft Graph sendMail request failed: %s', exc)
        return False

    if response.status_code == 202:
        return True

    if response.status_code == 401:
        clear_graph_tokens()
        app.logger.warning('Microsoft Graph access token expired while sending to %s', to_address)
    else:
        app.logger.error('Microsoft Graph sendMail failed (%s): %s', response.status_code, response.text)
    return False


@app.context_processor
def inject_globals():
    return {
        'current_user': get_current_user(),
        'current_year': datetime.utcnow().year,
    }


@app.route('/')
def index():
    listings = Listing.query.order_by(Listing.created_at.desc()).limit(6).all()
    gallery = BeforeAfter.query.order_by(BeforeAfter.created_at.desc()).limit(6).all()
    return render_template('index.html', listings=listings, gallery=gallery)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        full_name = request.form.get('full_name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not password:
            flash('Username and password are required.', 'error')
        elif not full_name:
            flash('Full name is required.', 'error')
        elif not email:
            flash('Please provide an email address.', 'error')
        elif not is_valid_email(email):
            flash('Email address is invalid.', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
        elif User.query.filter_by(email=email).first():
            flash('Email already in use. Please log in or use a different email.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        else:
            user = User(username=username, full_name=full_name, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            flash('Invalid username or password.', 'error')
        else:
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            session.permanent = remember_me
            flash('Logged in successfully.', 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('index'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))


@app.route('/listings')
def view_listings():
    listings = Listing.query.order_by(Listing.created_at.desc()).all()
    return render_template('listings.html', listings=listings)


@app.route('/gallery')
def before_after_gallery():
    items = BeforeAfter.query.order_by(BeforeAfter.created_at.desc()).all()
    return render_template('gallery.html', items=items)


@app.route('/quote', methods=['GET', 'POST'])
def quote():
    current_user = get_current_user()

    if request.method == 'POST':
        if not current_user:
            flash('Please log in to submit a quote request.', 'error')
            return redirect(url_for('quote'))

        quote_type = request.form.get('quote_type', '').strip()
        requester_name = request.form.get('requester_name', '').strip()
        notes = request.form.get('notes', '').strip()

        if not requester_name:
            flash('Please provide your name.', 'error')
            return redirect(url_for('quote'))

        quote_request = QuoteRequest(
            user_id=current_user.id,
            requester_name=requester_name,
            request_type=quote_type,
            notes=notes or None,
        )
        db.session.add(quote_request)
        db.session.flush()

        storage_base = os.path.join('quotes', str(current_user.id), str(quote_request.id))

        if quote_type == 'has_file':
            project_file = request.files.get('project_file')
            if not project_file or project_file.filename == '':
                db.session.rollback()
                flash('Please upload your STL or 3MF file.', 'error')
                return redirect(url_for('quote'))
            uploaded_path = save_uploaded_file(project_file, storage_base)
            if not uploaded_path:
                db.session.rollback()
                return redirect(url_for('quote'))
            quote_request.uploaded_filename = uploaded_path
        elif quote_type == 'needs_design':
            reference = request.files.get('reference_image')
            if reference and reference.filename:
                reference_path = save_uploaded_file(reference, os.path.join(storage_base, 'reference'))
                if not reference_path:
                    db.session.rollback()
                    return redirect(url_for('quote'))
                quote_request.reference_image_filename = reference_path
        else:
            db.session.rollback()
            flash('Invalid quote submission.', 'error')
            return redirect(url_for('quote'))

        db.session.commit()
        flash('Quote request received! We will review it and reach out soon.', 'success')
        return redirect(url_for('quote'))

    return render_template('quote.html', require_login=not bool(current_user), current_user=current_user)


@app.route('/quotes/messages')
@login_required
def quote_messages():
    user = get_current_user()
    quotes = QuoteRequest.query.filter_by(user_id=user.id) \
        .order_by(QuoteRequest.created_at.desc()).all()
    messages_by_quote = {}
    conversation_subjects = {}
    last_message_at = {}

    for quote in quotes:
        messages = QuoteMessage.query.filter_by(quote_id=quote.id) \
            .order_by(QuoteMessage.created_at.asc()).all()
        messages_by_quote[quote.id] = messages

        subject = next((m.subject for m in messages if m.subject), None)
        if not subject:
            subject = f"Quote #{quote.id} Conversation"
        conversation_subjects[quote.id] = subject

        if messages:
            last_message_at[quote.id] = messages[-1].created_at

    return render_template(
        'quote_messages.html',
        quotes=quotes,
        messages_by_quote=messages_by_quote,
        conversation_subjects=conversation_subjects,
        last_message_at=last_message_at,
    )


@app.route('/quotes/<int:quote_id>/messages', methods=['POST'])
@login_required
def user_send_quote_message(quote_id: int):
    user = get_current_user()
    quote_request = QuoteRequest.query.filter_by(id=quote_id, user_id=user.id).first()

    if not quote_request:
        flash('Quote request not found.', 'error')
        return redirect(url_for('quote_messages'))

    subject = request.form.get('subject', '').strip() or None
    message_body = request.form.get('message', '').strip()

    if not message_body:
        flash('Message cannot be empty.', 'error')
        return redirect(url_for('quote_messages', _anchor=f'quote-{quote_id}'))

    existing_messages = QuoteMessage.query.filter_by(quote_id=quote_request.id) \
        .order_by(QuoteMessage.created_at.asc()).all()
    existing_subject = next((m.subject for m in existing_messages if m.subject), None)

    final_subject = subject or existing_subject or f"Quote #{quote_request.id} Conversation"

    message = QuoteMessage(
        quote_id=quote_request.id,
        sender_id=user.id,
        sender_admin=False,
        subject=final_subject,
        body=message_body,
    )
    db.session.add(message)
    db.session.commit()

    flash('Message sent to the admin team.', 'success')
    return redirect(url_for('quote_messages', _anchor=f'quote-{quote_id}'))


@app.route('/messages')
@login_required
def user_messages():
    user = get_current_user()
    quotes = QuoteRequest.query.filter_by(user_id=user.id).order_by(QuoteRequest.created_at.desc()).all()
    return render_template('user_messages.html', quotes=quotes)


@app.route('/admin')
@admin_required
def admin_dashboard():
    listings = Listing.query.order_by(Listing.created_at.desc()).all()
    gallery = BeforeAfter.query.order_by(BeforeAfter.created_at.desc()).all()
    graph_status = {
        'configured': bool(app.config.get('MS_GRAPH_CLIENT_ID') and app.config.get('MS_GRAPH_CLIENT_SECRET')),
        'connected': is_graph_connected(),
        'redirect_uri': app.config.get('MS_GRAPH_REDIRECT_URI'),
        'scopes': app.config.get('MS_GRAPH_SCOPES'),
    }
    return render_template('admin.html', listings=listings, gallery=gallery, graph_status=graph_status)


@app.route('/admin/listings/add', methods=['POST'])
@admin_required
def add_listing():
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    price = request.form.get('price', '0').strip()
    image = request.files.get('image')

    try:
        price_value = float(price)
    except ValueError:
        price_value = -1

    if not title or not description or price_value <= 0:
        flash('Please provide a valid title, description, and price.', 'error')
        return redirect(url_for('admin_dashboard'))

    image_path = save_uploaded_file(image, 'listings')

    listing = Listing(
        title=title,
        description=description,
        price=price_value,
        image_filename=image_path,
    )
    db.session.add(listing)
    db.session.commit()
    flash('Listing added successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/listings/<int:listing_id>/delete', methods=['POST'])
@admin_required
def delete_listing(listing_id: int):
    listing = db.session.get(Listing, listing_id)
    if not listing:
        flash('Listing not found.', 'error')
        return redirect(url_for('admin_dashboard'))

    if listing.image_filename:
        try:
            os.remove(os.path.join(BASE_DIR, 'static', listing.image_filename))
        except OSError:
            pass

    db.session.delete(listing)
    db.session.commit()
    flash('Listing removed.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/gallery/add', methods=['POST'])
@admin_required
def add_before_after():
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    stl_image = request.files.get('stl_image')
    printed_image = request.files.get('printed_image')

    if not title:
        flash('Title is required for before & after entries.', 'error')
        return redirect(url_for('admin_dashboard'))

    stl_path = save_uploaded_file(stl_image, 'before_after')
    printed_path = save_uploaded_file(printed_image, 'before_after')

    entry = BeforeAfter(
        title=title,
        description=description,
        stl_filename=stl_path,
        printed_filename=printed_path,
    )
    db.session.add(entry)
    db.session.commit()
    flash('Before & after entry added.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/gallery/<int:item_id>/delete', methods=['POST'])
@admin_required
def delete_before_after(item_id: int):
    entry = db.session.get(BeforeAfter, item_id)
    if not entry:
        flash('Gallery entry not found.', 'error')
        return redirect(url_for('admin_dashboard'))

    for path in [entry.stl_filename, entry.printed_filename]:
        if path:
            try:
                os.remove(os.path.join(BASE_DIR, 'static', path))
            except OSError:
                pass

    db.session.delete(entry)
    db.session.commit()
    flash('Gallery entry removed.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/quotes')
@admin_required
def admin_quotes():
    active_requests = QuoteRequest.query.filter(QuoteRequest.deleted_at.is_(None)) \
        .order_by(QuoteRequest.created_at.desc()).all()
    return render_template('admin_quotes.html', active_requests=active_requests)


@app.route('/admin/quotes/<int:quote_id>')
@admin_required
def admin_quote_detail(quote_id: int):
    quote_request = db.session.get(QuoteRequest, quote_id)
    if not quote_request:
        flash('Quote request not found.', 'error')
        return redirect(url_for('admin_quotes'))

    messages = QuoteMessage.query.filter_by(quote_id=quote_request.id) \
        .order_by(QuoteMessage.created_at.asc()).all()
    conversation_subject = next((m.subject for m in messages if m.subject), None)
    if not conversation_subject:
        conversation_subject = f"Quote #{quote_request.id} Conversation"

    return render_template(
        'admin_quote_detail.html',
        quote=quote_request,
        messages=messages,
        conversation_subject=conversation_subject,
    )


@app.route('/admin/quotes/archived')
@admin_required
def admin_quotes_archived():
    deleted_cutoff = datetime.utcnow() - timedelta(days=30)
    deleted_requests = QuoteRequest.query.filter(QuoteRequest.deleted_at.is_not(None)) \
        .filter(QuoteRequest.deleted_at >= deleted_cutoff) \
        .order_by(QuoteRequest.deleted_at.desc()).all()
    return render_template('admin_quotes_archived.html', deleted_requests=deleted_requests)


@app.route('/admin/quotes/<int:quote_id>/message', methods=['POST'])
@admin_required
def admin_send_quote_message(quote_id: int):
    quote_request = db.session.get(QuoteRequest, quote_id)
    if not quote_request:
        flash('Quote request not found.', 'error')
        return redirect(url_for('admin_quotes'))

    message_body = request.form.get('message', '').strip()
    if not message_body:
        flash('Message cannot be empty.', 'error')
        return redirect(url_for('admin_quote_detail', quote_id=quote_id))

    existing_messages = QuoteMessage.query.filter_by(quote_id=quote_request.id) \
        .order_by(QuoteMessage.created_at.asc()).all()
    existing_subject = next((m.subject for m in existing_messages if m.subject), None)
    email_subject = existing_subject or f"Quote #{quote_request.id} Conversation"

    message = QuoteMessage(
        quote_id=quote_request.id,
        sender_id=get_current_user().id,
        subject=email_subject,
        body=message_body,
    )
    db.session.add(message)
    db.session.commit()

    email_body = (
        f"Hello {quote_request.requester_name},\n\n"
        f"You have a new message regarding your quote request (ID {quote_request.id}):\n\n"
        f"{message_body}\n\n"
        "Please log in to your drivenbyfaith3d account to reply or see more details."
    )
    email_sent = send_email(quote_request.user.email, email_subject, email_body)

    if email_sent:
        flash('Message sent to user and emailed.', 'success')
    else:
        flash('Message saved, but email failed to send. Connect Microsoft Graph and try again.', 'error')
    return redirect(url_for('admin_quote_detail', quote_id=quote_id))


@app.route('/admin/quotes/<int:quote_id>/delete', methods=['POST'])
@admin_required
def delete_quote(quote_id: int):
    quote_request = db.session.get(QuoteRequest, quote_id)
    if not quote_request:
        flash('Quote request not found.', 'error')
        return redirect(url_for('admin_quotes'))
    if quote_request.deleted_at:
        flash('Quote request already deleted.', 'info')
        return redirect(url_for('admin_quotes'))

    quote_request.deleted_at = datetime.utcnow()
    db.session.commit()
    flash('Quote request archived. It will remain available for 30 days.', 'success')
    return redirect(url_for('admin_quotes'))


@app.route('/admin/quotes/<int:quote_id>/delete-permanent', methods=['POST'])
@admin_required
def delete_quote_permanent(quote_id: int):
    quote_request = db.session.get(QuoteRequest, quote_id)
    if not quote_request:
        flash('Quote request not found.', 'error')
        return redirect(url_for('admin_quotes'))
    if not quote_request.deleted_at:
        flash('Archive the quote before permanently deleting it.', 'error')
        return redirect(url_for('admin_quotes'))

    # Remove associated files
    for path in [quote_request.uploaded_filename, quote_request.reference_image_filename]:
        if path:
            try:
                os.remove(os.path.join(BASE_DIR, 'static', path))
            except OSError:
                pass
    # Remove directory if empty
    quote_dir = os.path.join(BASE_DIR, 'static', 'uploads', 'quotes', str(quote_request.user_id), str(quote_request.id))
    if os.path.isdir(quote_dir):
        try:
            shutil.rmtree(quote_dir)
        except OSError:
            pass

    db.session.delete(quote_request)
    db.session.commit()
    flash('Quote request permanently deleted.', 'success')
    return redirect(url_for('admin_quotes'))


@app.route('/admin/quotes/<int:quote_id>/unarchive', methods=['POST'])
@admin_required
def unarchive_quote(quote_id: int):
    quote_request = db.session.get(QuoteRequest, quote_id)
    if not quote_request or not quote_request.deleted_at:
        flash('Quote request not found or not archived.', 'error')
        return redirect(url_for('admin_quotes_archived'))

    quote_request.deleted_at = None
    db.session.commit()
    flash('Quote request restored to active list.', 'success')
    return redirect(url_for('admin_quotes'))


@app.route('/admin/quotes/<int:quote_id>/messages', methods=['POST'])
@admin_required
def create_quote_message(quote_id: int):
    quote_request = db.session.get(QuoteRequest, quote_id)
    if not quote_request or quote_request.deleted_at:
        flash('Quote request not available for messaging.', 'error')
        return redirect(url_for('admin_quotes'))

    current_admin = get_current_user()
    if not current_admin:
        flash('Unable to determine current admin user.', 'error')
        return redirect(url_for('admin_quotes'))

    existing_messages = QuoteMessage.query.filter_by(quote_id=quote_request.id) \
        .order_by(QuoteMessage.created_at.asc()).all()
    existing_subject = next((m.subject for m in existing_messages if m.subject), None)

    subject = request.form.get('subject', '').strip()
    if not subject:
        subject = existing_subject or f"Quote #{quote_request.id} Conversation"
    body = request.form.get('body', '').strip()
    if not body:
        flash('Message body cannot be empty.', 'error')
        return redirect(url_for('admin_quotes'))

    message = QuoteMessage(
        quote_id=quote_request.id,
        sender_id=current_admin.id,
        sender_admin=True,
        subject=subject,
        body=body,
    )
    db.session.add(message)
    db.session.commit()

    email_body = f"Hello {quote_request.requester_name},\n\n{body}\n\n-- drivenbyfaith3d"
    email_sent = send_email(quote_request.user.email, subject, email_body)

    if email_sent:
        flash('Message sent to user.', 'success')
    else:
        flash('Message saved, but email failed to send. Connect Microsoft Graph and try again.', 'error')

    return redirect(url_for('admin_quotes'))


@app.route('/admin/email/test', methods=['POST'])
@admin_required
def admin_test_email():
    current_admin = get_current_user()
    target_email = request.form.get('email', '').strip() or (current_admin.email if current_admin else '')

    if not target_email or not is_valid_email(target_email):
        flash('Please provide a valid email address for testing.', 'error')
        return redirect(url_for('admin_dashboard'))

    if not is_graph_connected():
        flash('Connect your Microsoft account before sending test emails.', 'error')
        return redirect(url_for('admin_dashboard'))

    subject = 'drivenbyfaith3d Test Email'
    body = (
        f"Hello {current_admin.full_name if current_admin else 'Admin'},\n\n"
        "This is a test email sent via Microsoft Graph from the drivenbyfaith3d admin dashboard.\n"
        "If you received this, the Microsoft integration is configured correctly.\n\n"
        "Blessings,\n"
        "drivenbyfaith3d"
    )

    if send_email(target_email, subject, body):
        flash(f'Test email sent to {target_email}. Please check the inbox and spam folder.', 'success')
    else:
        flash('Failed to send test email. Reconnect Microsoft Graph and review the logs for details.', 'error')

    return redirect(url_for('admin_dashboard'))


@app.route('/integrations/microsoft/connect')
@admin_required
def microsoft_connect():
    if not session.get('is_admin'):
        flash('Administrator access required.', 'error')
        return redirect(url_for('login'))

    if not app.config.get('MS_GRAPH_CLIENT_ID') or not app.config.get('MS_GRAPH_CLIENT_SECRET'):
        flash('Microsoft Graph client ID and secret are not configured.', 'error')
        return redirect(url_for('admin_dashboard'))

    state = uuid.uuid4().hex
    session['graph_oauth_state'] = state
    authorization_url = build_graph_authorization_url(state)
    if not authorization_url:
        flash('Unable to initiate Microsoft Graph authorization. Check configuration.', 'error')
        return redirect(url_for('admin_dashboard'))

    return redirect(authorization_url)


@app.route('/oauth/callback')
def microsoft_callback():
    if not session.get('is_admin'):
        flash('Please sign in as an administrator before connecting Microsoft Graph.', 'error')
        return redirect(url_for('login'))

    if request.args.get('error'):
        description = request.args.get('error_description') or request.args['error']
        flash(f'Microsoft sign-in failed: {description}', 'error')
        return redirect(url_for('admin_dashboard'))

    expected_state = session.pop('graph_oauth_state', None)
    returned_state = request.args.get('state')
    if expected_state and expected_state != returned_state:
        flash('Microsoft authorization state mismatch. Please try again.', 'error')
        return redirect(url_for('admin_dashboard'))

    code = request.args.get('code')
    if not code:
        flash('Microsoft authorization code missing.', 'error')
        return redirect(url_for('admin_dashboard'))

    token_data = exchange_code_for_token(code)
    if not token_data:
        flash('Failed to complete Microsoft Graph authorization.', 'error')
        return redirect(url_for('admin_dashboard'))

    store_graph_tokens(token_data)
    flash('Microsoft account connected. Email notifications enabled.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/integrations/microsoft/disconnect', methods=['POST'])
@admin_required
def microsoft_disconnect():
    clear_graph_tokens()
    flash('Microsoft Graph connection removed.', 'info')
    return redirect(url_for('admin_dashboard'))


def initialize_database() -> None:
    db.create_all()

    admin_username = os.environ.get('DRIVENBYFAITH3D_ADMIN_USER', 'drivenbyfaith3d')
    admin_password = os.environ.get('DRIVENBYFAITH3D_ADMIN_PASS', 'Sue5743pond!')
    admin_email = os.environ.get('DRIVENBYFAITH3D_ADMIN_EMAIL', 'drivenbyfaith3d@outlook.com')

    existing_admin = User.query.filter_by(username=admin_username).first()

    if not existing_admin:
        admin = User(username=admin_username, is_admin=True, email=admin_email)
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        app.logger.info('Created default admin account. Please change the default password ASAP.')
    else:
        updated = False
        if not existing_admin.email:
            existing_admin.email = admin_email
            updated = True
        if updated:
            db.session.commit()


with app.app_context():
    initialize_database()


if __name__ == '__main__':
    app.run(debug=True)
