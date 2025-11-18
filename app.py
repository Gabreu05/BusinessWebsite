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
from sqlalchemy.orm import selectinload
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
database_url = os.environ.get('DATABASE_URL')
if database_url:
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = os.environ.get('DRIVENBYFAITH3D_SECRET', 'change-this-secret-key')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB upload limit
app.config['EMAILJS_SERVICE_ID'] = os.environ.get('EMAILJS_SERVICE_ID')
app.config['EMAILJS_TEMPLATE_ID'] = os.environ.get('EMAILJS_TEMPLATE_ID')
app.config['EMAILJS_PUBLIC_KEY'] = os.environ.get('EMAILJS_PUBLIC_KEY')
app.config['EMAILJS_PRIVATE_KEY'] = os.environ.get('EMAILJS_PRIVATE_KEY')

# Configure logging to a file
if not app.debug and not os.environ.get('VERCEL'):
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


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    quotes = db.relationship('QuoteRequest', backref='user', lazy=True)
    messages_sent = db.relationship('QuoteMessage', back_populates='sender', lazy='selectin')

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
    created_at = db.Column(db.DateTime, default=utcnow)


class BeforeAfter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    stl_filename = db.Column(db.String(255))
    printed_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=utcnow)


class QuoteRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requester_name = db.Column(db.String(120), nullable=False)
    request_type = db.Column(db.String(40), nullable=False)  # "has_file" or "needs_design"
    uploaded_filename = db.Column(db.String(255))
    reference_image_filename = db.Column(db.String(255))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=utcnow)
    deleted_at = db.Column(db.DateTime)
    messages = db.relationship(
        'QuoteMessage',
        backref='quote',
        lazy='selectin',
        cascade='all, delete-orphan',
        order_by='QuoteMessage.created_at'
    )


class QuoteMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quote_id = db.Column(db.Integer, db.ForeignKey('quote_request.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_admin = db.Column(db.Boolean, default=True)
    subject = db.Column(db.String(200))
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow)

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


def send_email(to_address: str, subject: str, body: str) -> bool:
    service_id = app.config.get('EMAILJS_SERVICE_ID')
    template_id = app.config.get('EMAILJS_TEMPLATE_ID')
    public_key = app.config.get('EMAILJS_PUBLIC_KEY')
    private_key = app.config.get('EMAILJS_PRIVATE_KEY')

    if not all([service_id, template_id, public_key, private_key]):
        app.logger.warning('EmailJS credentials missing; skipping email to %s', to_address)
        return False

    payload = {
        'service_id': service_id,
        'template_id': template_id,
        'user_id': public_key,
        'template_params': {
            'to_email': to_address,
            'subject': subject,
            'message': body,
        },
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {private_key}',
    }

    try:
        response = requests.post(
            'https://api.emailjs.com/api/v1.0/email/send',
            json=payload,
            headers=headers,
            timeout=10,
        )
    except requests.RequestException as exc:
        app.logger.error('EmailJS request failed: %s', exc)
        return False

    if response.status_code == 200:
        return True

    app.logger.error('EmailJS send failed (%s): %s', response.status_code, response.text)
    return False


def emailjs_configured() -> bool:
    return all(
        [
            app.config.get('EMAILJS_SERVICE_ID'),
            app.config.get('EMAILJS_TEMPLATE_ID'),
            app.config.get('EMAILJS_PUBLIC_KEY'),
            app.config.get('EMAILJS_PRIVATE_KEY'),
        ]
    )


def send_quote_submission_email(quote_request: QuoteRequest) -> bool:
    user = quote_request.user
    if not user or not user.email:
        app.logger.warning('Quote %s has no associated user email; cannot send confirmation.', quote_request.id)
        return False

    requester = quote_request.requester_name or user.full_name or user.username
    quote_id = quote_request.id

    if quote_request.request_type == 'has_file':
        subject = f"Quote #{quote_id}: Files received"
        body = (
            f"Hello {requester},\n\n"
            "Thanks for sending your model files to drivenbyfaith3d. "
            "We’ll review them and respond with pricing and timeline details shortly."
            f"\n\nReference ID: #{quote_id}\n\nBlessings,\ndrivenbyfaith3d"
        )
    else:
        subject = f"Quote #{quote_id}: Design request received"
        body = (
            f"Hello {requester},\n\n"
            "Thanks for reaching out about a custom design. "
            "We’ll look over your notes and follow up to discuss the details and next steps."
            f"\n\nReference ID: #{quote_id}\n\nBlessings,\ndrivenbyfaith3d"
        )

    return send_email(user.email, subject, body)


@app.context_processor
def inject_globals():
    return {
        'current_user': get_current_user(),
        'current_year': utcnow().year,
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

        if not send_quote_submission_email(quote_request):
            app.logger.warning('Automated quote confirmation failed for quote %s.', quote_request.id)

        flash('Quote request received! We will review it and reach out soon.', 'success')
        return redirect(url_for('quote'))

    return render_template('quote.html', require_login=not bool(current_user), current_user=current_user)


@app.route('/quotes/messages')
@login_required
def quote_messages():
    user = get_current_user()
    quotes = (
        QuoteRequest.query.filter_by(user_id=user.id)
        .options(
            selectinload(QuoteRequest.messages).selectinload(QuoteMessage.sender)
        )
        .order_by(QuoteRequest.created_at.desc())
        .all()
    )

    messages_by_quote = {quote.id: list(quote.messages) for quote in quotes}
    conversation_subjects = {}
    last_message_at = {}

    for quote in quotes:
        messages = messages_by_quote[quote.id]
        conversation_subjects[quote.id] = conversation_subject_for(messages, quote.id)
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
    email_status = {
        'configured': emailjs_configured(),
    }
    return render_template('admin.html', listings=listings, gallery=gallery, email_status=email_status)


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
    quote_request = (
        QuoteRequest.query.options(
            selectinload(QuoteRequest.messages).selectinload(QuoteMessage.sender)
        ).get(quote_id)
    )
    if not quote_request:
        flash('Quote request not found.', 'error')
        return redirect(url_for('admin_quotes'))

    messages = list(quote_request.messages)
    conversation_subject = conversation_subject_for(messages, quote_request.id)

    return render_template(
        'admin_quote_detail.html',
        quote=quote_request,
        messages=messages,
        conversation_subject=conversation_subject,
    )


@app.route('/admin/quotes/archived')
@admin_required
def admin_quotes_archived():
    deleted_cutoff = utcnow() - timedelta(days=30)
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
    email_subject = conversation_subject_for(existing_messages, quote_request.id)

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
        flash('Message saved, but email failed to send. Verify EmailJS configuration and try again.', 'error')
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

    quote_request.deleted_at = utcnow()
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

    existing_messages = list(quote_request.messages)

    subject = request.form.get('subject', '').strip()
    if not subject:
        subject = conversation_subject_for(existing_messages, quote_request.id)

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
        flash('Message saved, but email failed to send. Verify EmailJS configuration and try again.', 'error')

    return redirect(url_for('admin_quotes'))


@app.route('/admin/email/test', methods=['POST'])
@admin_required
def admin_test_email():
    current_admin = get_current_user()
    target_email = request.form.get('email', '').strip() or (current_admin.email if current_admin else '')

    if not target_email or not is_valid_email(target_email):
        flash('Please provide a valid email address for testing.', 'error')
        return redirect(url_for('admin_dashboard'))

    body = (
        f"Hello {current_admin.full_name if current_admin else 'Admin'},\n\n"
        "This is a test email sent via EmailJS from the drivenbyfaith3d dashboard.\n\n"
        "-- drivenbyfaith3d"
    )

    if send_email(target_email, 'drivenbyfaith3d Test Email', body):
        flash(f'Test email sent to {target_email}. Please check the inbox and spam folder.', 'success')
    else:
        flash('Failed to send test email. Verify EmailJS configuration.', 'error')

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


def conversation_subject_for(messages, quote_id: int) -> str:
    subject = next((m.subject for m in messages if getattr(m, 'subject', None)), None)
    return subject or f"Quote #{quote_id} Conversation"


with app.app_context():
    initialize_database()


if __name__ == '__main__':
    app.run(debug=True)
