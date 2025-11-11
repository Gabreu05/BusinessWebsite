import os
import re
import uuid
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(BASE_DIR, 'static', 'uploads')
LISTING_UPLOAD_DIR = os.path.join(UPLOAD_ROOT, 'listings')
BEFORE_AFTER_UPLOAD_DIR = os.path.join(UPLOAD_ROOT, 'before_after')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = os.environ.get('DRIVENBYFAITH3D_SECRET', 'change-this-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB upload limit

# Ensure upload directories exist
os.makedirs(LISTING_UPLOAD_DIR, exist_ok=True)
os.makedirs(BEFORE_AFTER_UPLOAD_DIR, exist_ok=True)

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    contact = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    material = db.Column(db.String(80), nullable=False)
    volume_cm3 = db.Column(db.Float, nullable=False)
    complexity = db.Column(db.String(40), nullable=False)
    notes = db.Column(db.Text)
    estimated_cost = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


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


def is_valid_contact(value: str) -> bool:
    if not value:
        return False

    email_pattern = r'^[^@\s]+@[^@\s]+\.[^@\s]+$'
    phone_digits = re.sub(r'\D', '', value)

    return bool(re.match(email_pattern, value)) or 10 <= len(phone_digits) <= 15


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
        contact = request.form.get('contact', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not username or not password:
            flash('Username and password are required.', 'error')
        elif not contact:
            flash('Please provide an email address or phone number.', 'error')
        elif not is_valid_contact(contact):
            flash('Contact information must be a valid email or phone number.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        elif User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
        else:
            user = User(username=username, contact=contact)
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
    estimate = None

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        material = request.form.get('material', '').strip()
        volume_input = request.form.get('volume_cm3', '').strip()
        complexity = request.form.get('complexity', '').strip()
        notes = request.form.get('notes', '').strip()

        try:
            volume_cm3 = float(volume_input)
        except ValueError:
            volume_cm3 = -1

        if not name or not email or not material or not complexity or volume_cm3 <= 0:
            flash('Please fill in all required fields with valid data.', 'error')
        else:
            material_rates = {
                'pla': 0.20,
                'abs': 0.25,
                'petg': 0.23,
                'resin': 0.45,
            }
            complexity_multiplier = {
                'low': 1.0,
                'medium': 1.25,
                'high': 1.5,
            }

            base_rate = material_rates.get(material.lower(), 0.30)
            multiplier = complexity_multiplier.get(complexity.lower(), 1.0)
            estimate = round(volume_cm3 * base_rate * multiplier + 5.0, 2)

            quote_request = QuoteRequest(
                name=name,
                email=email,
                material=material,
                volume_cm3=volume_cm3,
                complexity=complexity,
                notes=notes,
                estimated_cost=estimate,
            )
            db.session.add(quote_request)
            db.session.commit()
            flash('Quote generated successfully!', 'success')

    return render_template('quote.html', estimate=estimate)


@app.route('/admin')
@admin_required
def admin_dashboard():
    listings = Listing.query.order_by(Listing.created_at.desc()).all()
    gallery = BeforeAfter.query.order_by(BeforeAfter.created_at.desc()).all()
    return render_template('admin.html', listings=listings, gallery=gallery)


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


def initialize_database() -> None:
    db.create_all()

    admin_username = os.environ.get('DRIVENBYFAITH3D_ADMIN_USER', 'admin')
    admin_password = os.environ.get('DRIVENBYFAITH3D_ADMIN_PASS', 'admin123')
    admin_contact = os.environ.get('DRIVENBYFAITH3D_ADMIN_CONTACT', 'admin@example.com')

    existing_admin = User.query.filter_by(username=admin_username).first()

    if not existing_admin:
        admin = User(username=admin_username, is_admin=True, contact=admin_contact)
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        app.logger.info('Created default admin account. Please change the default password ASAP.')
    else:
        if not existing_admin.contact:
            existing_admin.contact = admin_contact
            db.session.commit()


with app.app_context():
    initialize_database()


if __name__ == '__main__':
    app.run(debug=True)
