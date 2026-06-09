"""
Azhar Al-Sanabel - Premium Flower Shop
Secure Flask Application with Admin Dashboard
"""
import os
import re
import random
import string
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, abort, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from bleach import clean as bleach_clean
from email_validator import validate_email as email_validate, EmailNotValidError
from dotenv import load_dotenv
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_admin.form import SecureForm

# Load environment variables
load_dotenv()

# Initialize Flask
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(32).hex())
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///azhar_alsanabel.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = set(os.environ.get('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,webp').split(','))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(os.environ.get('PERMANENT_SESSION_LIFETIME', 3600)))
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')

# Security Headers via Talisman
csp = {
    'default-src': "'self'",
    'script-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com", "https://unpkg.com"],
    'style-src': ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
    'font-src': ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
    'img-src': ["'self'", "data:", "https:", "blob:"],
    'connect-src': ["'self'"],
    'frame-src': ["https://www.google.com"],
}
Talisman(app, content_security_policy=csp, force_https=False)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=os.environ.get('RATELIMIT_STORAGE_URI', 'memory://'),
    strategy=os.environ.get('RATELIMIT_STRATEGY', 'fixed-window'),
    default_limits=["200 per day", "50 per hour"]
)

# Database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Logging
if not os.path.exists('logs'):
    os.makedirs('logs')
file_handler = logging.FileHandler('logs/app.log')
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
file_handler.setFormatter(formatter)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Azhar Al-Sanabel startup')

# ==============================================================================
# MODELS
# ==============================================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    address = db.Column(db.String(255))
    city = db.Column(db.String(100))
    governorate = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    orders = db.relationship('Order', backref='user', lazy='dynamic')
    chat_messages = db.relationship('ChatMessage', backref='user', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'phone': self.phone,
            'address': self.address,
            'city': self.city,
            'governorate': self.governorate,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False, index=True)
    image = db.Column(db.String(500))
    stock = db.Column(db.Integer, default=10)
    badge = db.Column(db.String(50))
    featured = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    order_items = db.relationship('OrderItem', backref='product', lazy='dynamic')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'category': self.category,
            'image': self.image,
            'stock': self.stock,
            'badge': self.badge,
            'featured': self.featured
        }

class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(20), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    customer_name = db.Column(db.String(100))
    customer_email = db.Column(db.String(120))
    customer_phone = db.Column(db.String(20))
    shipping_address = db.Column(db.String(255))
    city = db.Column(db.String(100))
    governorate = db.Column(db.String(100))
    payment_method = db.Column(db.String(50), default='cash')
    notes = db.Column(db.Text)
    total = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('OrderItem', backref='order', lazy='dynamic', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.order_id,
            'total': self.total,
            'status': self.status,
            'date': self.created_at.isoformat() if self.created_at else None,
            'payment_method': self.payment_method,
            'customer_name': self.customer_name,
            'customer_email': self.customer_email
        }

class OrderItem(db.Model):
    __tablename__ = 'order_items'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.String(20), db.ForeignKey('orders.order_id'))
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    product_name = db.Column(db.String(200))
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)

class ContactMessage(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    subject = db.Column(db.String(200))
    message = db.Column(db.Text)
    status = db.Column(db.String(50), default='new')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120))
    message = db.Column(db.Text)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SiteSetting(db.Model):
    __tablename__ = 'site_settings'
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ==============================================================================
# ADMIN PANEL (Secure)
# ==============================================================================

class SecureAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not self.is_accessible():
            return redirect(url_for('index'))

        # Dashboard stats
        stats = {
            'total_users': User.query.count(),
            'total_orders': Order.query.count(),
            'total_products': Product.query.count(),
            'pending_orders': Order.query.filter_by(status='pending').count(),
            'total_revenue': db.session.query(db.func.sum(Order.total)).scalar() or 0,
            'recent_orders': Order.query.order_by(Order.created_at.desc()).limit(5).all(),
            'recent_messages': ContactMessage.query.order_by(ContactMessage.created_at.desc()).limit(5).all()
        }
        return self.render('admin/dashboard.html', stats=stats)

    def is_accessible(self):
        if 'user_id' not in session:
            return False
        user = User.query.get(session['user_id'])
        return user is not None and user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        flash('You must be an admin to access this page.', 'error')
        return redirect(url_for('index'))

class SecureModelView(ModelView):
    form_base_class = SecureForm

    def is_accessible(self):
        if 'user_id' not in session:
            return False
        user = User.query.get(session['user_id'])
        return user is not None and user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        flash('You must be an admin to access this page.', 'error')
        return redirect(url_for('index'))

admin = Admin(app, name='Azhar Al-Sanabel Admin', 
              template_mode='bootstrap4',
              index_view=SecureAdminIndexView(),
              base_template='admin/base.html')

admin.add_view(SecureModelView(User, db.session, name='Users'))
admin.add_view(SecureModelView(Product, db.session, name='Products'))
admin.add_view(SecureModelView(Order, db.session, name='Orders'))
admin.add_view(SecureModelView(ContactMessage, db.session, name='Messages'))
admin.add_view(SecureModelView(ChatMessage, db.session, name='Chat'))
admin.add_view(SecureModelView(SiteSetting, db.session, name='Settings'))

# ==============================================================================
# SECURITY HELPERS
# ==============================================================================

def sanitize_input(text, max_length=1000):
    """Sanitize user input to prevent XSS"""
    if not text:
        return ''
    text = str(text)[:max_length]
    return bleach_clean(text, tags=[], strip=True)

def validate_email_secure(email):
    """Validate email securely"""
    try:
        info = email_validate(email, check_deliverability=False)
        return info.normalized
    except EmailNotValidError:
        return None

def validate_phone_jo(phone):
    """Validate Jordanian phone number"""
    return re.match(r'^(07[789]\d{7})$', phone) is not None

def validate_password_strength(password):
    """Check password strength"""
    if len(password) < 8:
        return False, 'Password must be at least 8 characters'
    if not re.search(r'[A-Z]', password):
        return False, 'Password must contain at least one uppercase letter'
    if not re.search(r'[a-z]', password):
        return False, 'Password must contain at least one lowercase letter'
    if not re.search(r'\d', password):
        return False, 'Password must contain at least one digit'
    return True, None

def gen_order_id():
    """Generate unique order ID"""
    return 'AZH-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

GOVERNORATES = [
    "Irbid", "Ajloun", "Jerash", "Mafraq", "Balqa", "Amman", 
    "Zarqa", "Madaba", "Karak", "Tafilah", "Ma'an", "Aqaba"
]

# ==============================================================================
# DECORATORS
# ==============================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        user = User.query.get(session['user_id'])
        if not user or not user.is_active:
            session.pop('user_id', None)
            return jsonify({'error': 'Invalid session'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Admin access required'}), 403
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# ==============================================================================
# ERROR HANDLERS
# ==============================================================================

@app.errorhandler(404)
def not_found(error):
    if request.is_json or request.headers.get('Accept', '').startswith('application/json'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Server Error: {error}')
    if request.is_json or request.headers.get('Accept', '').startswith('application/json'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('errors/500.html'), 500

@app.errorhandler(429)
def rate_limit_handler(error):
    if request.is_json or request.headers.get('Accept', '').startswith('application/json'):
        return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
    return render_template('errors/429.html'), 429

# ==============================================================================
# ROUTES
# ==============================================================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin/login')
def admin_login_redirect():
    """Redirect to main auth for admin access"""
    return redirect(url_for('index'))

# ==============================================================================
# AUTHENTICATION API
# ==============================================================================

@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    name = sanitize_input(data.get('name', ''), 100).strip()
    email = sanitize_input(data.get('email', ''), 120).strip().lower()
    phone = sanitize_input(data.get('phone', ''), 20).strip()
    password = data.get('password', '')

    # Validation
    if not all([name, email, phone, password]):
        return jsonify({'error': 'All fields are required'}), 400

    valid_email = validate_email_secure(email)
    if not valid_email:
        return jsonify({'error': 'Invalid email address'}), 400
    email = valid_email

    if not validate_phone_jo(phone):
        return jsonify({'error': 'Phone must start with 07 and be 10 digits'}), 400

    strong, msg = validate_password_strength(password)
    if not strong:
        return jsonify({'error': msg}), 400

    # Check existing
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400

    # Create user
    user = User(name=name, email=email, phone=phone)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    session['user_id'] = user.id
    session.permanent = True
    app.logger.info(f'New user registered: {email}')

    return jsonify({'success': True, 'user': user.to_dict()})

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    email = sanitize_input(data.get('email', ''), 120).strip().lower()
    password = data.get('password', '')

    if not all([email, password]):
        return jsonify({'error': 'Email and password required'}), 400

    valid_email = validate_email_secure(email)
    if valid_email:
        email = valid_email

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401

    if not user.is_active:
        return jsonify({'error': 'Account is deactivated'}), 403

    session['user_id'] = user.id
    session.permanent = True
    app.logger.info(f'User logged in: {email}')

    return jsonify({'success': True, 'user': user.to_dict()})

@app.route('/api/logout', methods=['POST'])
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        app.logger.info(f'User logged out: {user.email if user else "unknown"}')
    session.pop('user_id', None)
    return jsonify({'success': True})

@app.route('/api/me')
def me():
    if 'user_id' not in session:
        return jsonify({'logged_in': False})
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        return jsonify({'logged_in': False})
    return jsonify({'logged_in': True, 'user': user.to_dict()})

@app.route('/api/update-profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Update profile fields
    allowed_fields = ['name', 'phone', 'address', 'city', 'governorate']
    for field in allowed_fields:
        if field in data:
            setattr(user, field, sanitize_input(data[field], 255))

    # Phone validation
    if 'phone' in data and not validate_phone_jo(user.phone):
        return jsonify({'error': 'Invalid phone number'}), 400

    # Password change
    if data.get('new_password'):
        current = data.get('current_password', '')
        if not user.check_password(current):
            return jsonify({'error': 'Current password is incorrect'}), 400
        strong, msg = validate_password_strength(data['new_password'])
        if not strong:
            return jsonify({'error': msg}), 400
        user.set_password(data['new_password'])

    db.session.commit()
    app.logger.info(f'Profile updated for user: {user.email}')
    return jsonify({'success': True, 'user': user.to_dict()})

# ==============================================================================
# PRODUCTS API
# ==============================================================================

@app.route('/api/products')
def get_products():
    category = request.args.get('category', 'all')
    search = sanitize_input(request.args.get('search', ''), 100).lower()
    sort = request.args.get('sort', 'id')

    query = Product.query

    if category != 'all':
        query = query.filter_by(category=category)

    if search:
        query = query.filter(
            db.or_(
                Product.name.ilike(f'%{search}%'),
                Product.description.ilike(f'%{search}%')
            )
        )

    if sort == 'price_asc':
        query = query.order_by(Product.price.asc())
    elif sort == 'price_desc':
        query = query.order_by(Product.price.desc())
    elif sort == 'name':
        query = query.order_by(Product.name.asc())
    else:
        query = query.order_by(Product.id.asc())

    products = query.all()
    return jsonify([p.to_dict() for p in products])

@app.route('/api/product/<int:pid>')
def get_product(pid):
    product = Product.query.get(pid)
    if not product:
        return jsonify({'error': 'Product not found'}), 404
    return jsonify(product.to_dict())

# ==============================================================================
# ORDERS API
# ==============================================================================

@app.route('/api/order', methods=['POST'])
@limiter.limit("10 per minute")
def create_order():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    items = data.get('items', [])
    customer = data.get('customer', {})

    if not items:
        return jsonify({'error': 'Cart is empty'}), 400

    # Validate customer info
    customer_name = sanitize_input(customer.get('name', ''), 100)
    customer_email = sanitize_input(customer.get('email', ''), 120)
    customer_phone = sanitize_input(customer.get('phone', ''), 20)

    if not all([customer_name, customer_email, customer_phone]):
        return jsonify({'error': 'Customer information is required'}), 400

    # Process items
    total = 0
    order_items = []

    for item in items:
        product_id = item.get('product_id')
        quantity = item.get('quantity', 1)

        if not isinstance(product_id, int) or not isinstance(quantity, int):
            return jsonify({'error': 'Invalid item data'}), 400

        product = Product.query.get(product_id)
        if not product:
            return jsonify({'error': f'Product not found: {product_id}'}), 400

        if product.stock < quantity:
            return jsonify({'error': f'Not enough stock for {product.name}'}), 400

        if quantity <= 0:
            return jsonify({'error': 'Invalid quantity'}), 400

        total += product.price * quantity
        order_items.append({
            'product': product,
            'quantity': quantity,
            'price': product.price
        })

    total += 5.0  # Shipping
    order_id = gen_order_id()
    uid = session.get('user_id')

    # Create order
    order = Order(
        order_id=order_id,
        user_id=uid,
        customer_name=customer_name,
        customer_email=customer_email,
        customer_phone=customer_phone,
        shipping_address=sanitize_input(customer.get('address', ''), 255),
        city=sanitize_input(customer.get('city', ''), 100),
        governorate=sanitize_input(customer.get('governorate', ''), 100),
        payment_method=sanitize_input(customer.get('payment_method', 'cash'), 50),
        notes=sanitize_input(customer.get('notes', ''), 1000),
        total=total
    )
    db.session.add(order)
    db.session.flush()

    # Create order items and update stock
    for item in order_items:
        oi = OrderItem(
            order_id=order_id,
            product_id=item['product'].id,
            product_name=item['product'].name,
            quantity=item['quantity'],
            price=item['price']
        )
        db.session.add(oi)
        item['product'].stock -= item['quantity']

    db.session.commit()
    app.logger.info(f'Order created: {order_id}')

    return jsonify({'success': True, 'order_id': order_id, 'total': total})

@app.route('/api/orders')
@login_required
def get_orders():
    user = User.query.get(session['user_id'])
    orders = Order.query.filter_by(user_id=user.id).order_by(Order.created_at.desc()).all()

    result = []
    for o in orders:
        items = ', '.join([f"{oi.product_name} x{oi.quantity}" for oi in o.items])
        result.append({
            'id': o.order_id,
            'total': o.total,
            'status': o.status,
            'date': o.created_at.isoformat() if o.created_at else None,
            'items': items,
            'payment_method': o.payment_method
        })

    return jsonify(result)

@app.route('/api/order/<order_id>')
def get_order_public(order_id):
    """Allow order tracking without login"""
    order = Order.query.filter_by(order_id=order_id).first()
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    items = [{'name': oi.product_name, 'quantity': oi.quantity, 'price': oi.price} for oi in order.items]
    return jsonify({
        'order_id': order.order_id,
        'status': order.status,
        'total': order.total,
        'date': order.created_at.isoformat() if order.created_at else None,
        'items': items,
        'customer_name': order.customer_name
    })

# ==============================================================================
# CONTACT & CHAT API
# ==============================================================================

@app.route('/api/contact', methods=['POST'])
@limiter.limit("5 per minute")
def contact():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    msg = ContactMessage(
        name=sanitize_input(data.get('name', ''), 100),
        email=sanitize_input(data.get('email', ''), 120),
        phone=sanitize_input(data.get('phone', ''), 20),
        subject=sanitize_input(data.get('subject', ''), 200),
        message=sanitize_input(data.get('message', ''), 5000)
    )
    db.session.add(msg)
    db.session.commit()
    app.logger.info(f'Contact message from: {msg.email}')
    return jsonify({'success': True})

@app.route('/api/chat', methods=['POST'])
@limiter.limit("20 per minute")
def chat():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    uid = session.get('user_id')
    msg = ChatMessage(
        user_id=uid,
        name=sanitize_input(data.get('name', 'Guest'), 100),
        email=sanitize_input(data.get('email', ''), 120),
        message=sanitize_input(data.get('message', ''), 2000)
    )
    db.session.add(msg)
    db.session.commit()
    return jsonify({'success': True})

# ==============================================================================
# UTILITIES
# ==============================================================================

@app.route('/api/governorates')
def governorates():
    return jsonify(GOVERNORATES)

@app.route('/api/featured-products')
def featured_products():
    products = Product.query.filter_by(featured=True).limit(4).all()
    if not products:
        products = Product.query.limit(4).all()
    return jsonify([p.to_dict() for p in products])

# ==============================================================================
# ADMIN API
# ==============================================================================

@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    return jsonify({
        'users': User.query.count(),
        'orders': Order.query.count(),
        'products': Product.query.count(),
        'pending_orders': Order.query.filter_by(status='pending').count(),
        'revenue': float(db.session.query(db.func.sum(Order.total)).scalar() or 0),
        'messages': ContactMessage.query.filter_by(status='new').count()
    })

@app.route('/api/admin/orders')
@admin_required
def admin_orders():
    orders = Order.query.order_by(Order.created_at.desc()).all()
    return jsonify([{
        'order_id': o.order_id,
        'customer': o.customer_name,
        'total': o.total,
        'status': o.status,
        'date': o.created_at.isoformat() if o.created_at else None
    } for o in orders])

@app.route('/api/admin/order/<order_id>/status', methods=['POST'])
@admin_required
def update_order_status(order_id):
    data = request.get_json()
    order = Order.query.filter_by(order_id=order_id).first()
    if not order:
        return jsonify({'error': 'Order not found'}), 404

    valid_statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled']
    new_status = sanitize_input(data.get('status', ''), 50)
    if new_status not in valid_statuses:
        return jsonify({'error': 'Invalid status'}), 400

    order.status = new_status
    db.session.commit()
    app.logger.info(f'Order {order_id} status changed to {new_status}')
    return jsonify({'success': True})

# ==============================================================================
# DATABASE SEEDING
# ==============================================================================

def seed_database():
    """Seed database with initial data"""
    with app.app_context():
        db.create_all()

        # Create admin user if not exists
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin@azhar-alsanabel.com')
        admin_pass = os.environ.get('ADMIN_PASSWORD', 'AdminPass123!')

        if not User.query.filter_by(email=admin_email).first():
            admin_user = User(
                name='Administrator',
                email=admin_email,
                phone='0790000000',
                is_admin=True,
                is_active=True
            )
            admin_user.set_password(admin_pass)
            db.session.add(admin_user)
            app.logger.info(f'Admin user created: {admin_email}')

        # Seed products if empty
        if Product.query.count() == 0:
            products_data = [
                ("Red Rose Love Bouquet", "Luxurious bouquet of 12 natural red roses, perfect for expressing love and passion", 35.0, "bouquets", "https://images.unsplash.com/photo-1518621736915-f3b1c41bfd00?w=600", 20, "BESTSELLER", True),
                ("Bridal White Lily", "Elegant wedding bouquet of white lilies and roses, adding magic to your special day", 120.0, "bridal", "https://images.unsplash.com/photo-1594552072238-b8a33785b261?w=600", 15, "EXCLUSIVE", True),
                ("Pink Dream Collection", "Romantic bouquet of pink roses and peonies, ideal for Valentine's and special occasions", 55.0, "bouquets", "https://images.unsplash.com/photo-1561181286-d3fee7d55364?w=600", 18, "FEATURED", True),
                ("Sunshine Sunflower", "Bright sunflower bouquet bringing joy and optimism to any occasion", 45.0, "bouquets", "https://images.unsplash.com/photo-1597848212624-a19eb35e2651?w=600", 25, "BESTSELLER", True),
                ("Peony Paradise", "Premium arrangement of pink peonies in an elegant and unique design", 75.0, "gifts", "https://images.unsplash.com/photo-1563241527-3004b7be025f?w=600", 12, "PREMIUM", False),
                ("White Calla Lily", "Elegant bouquet of white calla lilies, symbol of purity and elegance", 65.0, "bouquets", "https://images.unsplash.com/photo-1508610048659-a06b669e3321?w=600", 10, "EXCLUSIVE", False),
                ("Golden Wedding Collection", "Luxurious wedding arrangement of roses and lilies with golden touches", 150.0, "bridal", "https://images.unsplash.com/photo-1526047932273-341f2a7631f9?w=600", 8, "PREMIUM", False),
                ("Fragrant Rose Gift Box", "Luxury gift box containing a rose bouquet with chocolate and balloon", 85.0, "gifts", "https://images.unsplash.com/photo-1582794543139-8ac92a900275?w=600", 20, "FEATURED", False),
                ("Wedding Car Decoration", "Full wedding car decoration with natural flowers and silk ribbons", 200.0, "decor", "https://images.unsplash.com/photo-1522673607200-1645062cd958?w=600", 5, "EXCLUSIVE", False),
                ("Mixed Rose Bouquet", "Beautiful mix of roses in different colors in a modern arrangement", 50.0, "bouquets", "https://images.unsplash.com/photo-1494972308805-463bc619d34e?w=600", 30, None, False),
                ("Purple Tulip Royal", "Elegant purple tulip bouquet, symbol of royalty and luxury", 60.0, "bouquets", "https://images.unsplash.com/photo-1520763185298-1b434c919102?w=600", 15, None, False),
                ("Luxury Flower Box", "Premium wooden box decorated with natural flowers and green leaves", 95.0, "gifts", "https://images.unsplash.com/photo-1487070183336-b863922373d4?w=600", 10, "PREMIUM", False),
            ]

            for p in products_data:
                product = Product(
                    name=p[0], description=p[1], price=p[2], category=p[3],
                    image=p[4], stock=p[5], badge=p[6], featured=p[7]
                )
                db.session.add(product)

            app.logger.info('Products seeded')

        # Default settings
        defaults = {
            'shop_name': 'Azhar Al-Sanabel',
            'shop_phone': os.environ.get('SHOP_PHONE', '+962 79 123 4567'),
            'shop_whatsapp': os.environ.get('SHOP_WHATSAPP', '+962791234567'),
            'shop_email': os.environ.get('SHOP_EMAIL', 'info@azhar-alsanabel.com'),
            'shop_address': os.environ.get('SHOP_ADDRESS', 'Irbid, Hashemite Kingdom of Jordan'),
            'currency': 'JOD',
            'shipping_cost': '5.0',
        }

        for key, value in defaults.items():
            if not SiteSetting.query.filter_by(key=key).first():
                db.session.add(SiteSetting(key=key, value=value))

        db.session.commit()
        app.logger.info('Database seeded successfully')

# Seed on startup
with app.app_context():
    seed_database()

# ==============================================================================
# MAIN
# ==============================================================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
