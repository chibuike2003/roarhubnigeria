import os
import logging
from datetime import datetime, date, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import smtplib
from email.mime.text import MIMEText
from functools import wraps

from email.mime.multipart import MIMEMultipart
from werkzeug.utils import secure_filename
import uuid
from sqlalchemy.exc import IntegrityError # Import IntegrityError


# --- Flask Application Setup ---
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_dev')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hub.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db) 

# --- File Upload Configuration for Profile Pics ---
UPLOAD_FOLDER = 'static/profile_pics'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- NEW: File Upload Configuration for Blog Media ---
UPLOAD_BLOG_FOLDER = 'static/blog_media'
app.config['UPLOAD_BLOG_FOLDER'] = UPLOAD_BLOG_FOLDER
BLOG_ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
BLOG_ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'webm', 'ogg'}

if not os.path.exists(UPLOAD_BLOG_FOLDER):
    os.makedirs(UPLOAD_BLOG_FOLDER)

# --- NEW: File Upload Configuration for Event Media ---
UPLOAD_EVENT_FOLDER = 'static/event_media'
app.config['UPLOAD_EVENT_FOLDER'] = UPLOAD_EVENT_FOLDER
EVENT_ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
EVENT_ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'webm', 'ogg'}

if not os.path.exists(UPLOAD_EVENT_FOLDER):
    os.makedirs(UPLOAD_EVENT_FOLDER)

# --- Flask-Login Setup for Users ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database based on their ID (for Flask-Login)."""
    user = User.query.get(int(user_id))
    if user:
        return user
    
    admin = Admin.query.get(int(user_id))
    if admin:
        return admin
    
    return None


# --- Logging Setup ---
logging.basicConfig(filename='user_activity.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper functions for allowed file extensions ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_blog_image_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in BLOG_ALLOWED_IMAGE_EXTENSIONS

def allowed_blog_video_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in BLOG_ALLOWED_VIDEO_EXTENSIONS

def allowed_event_image_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in EVENT_ALLOWED_IMAGE_EXTENSIONS

def allowed_event_video_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in EVENT_ALLOWED_VIDEO_EXTENSIONS


# --- Password Reset Token Helper ---
def generate_reset_token(user_or_admin):
    """Generates a unique token and sets its expiration (e.g., 1 hour)."""
    # Generate a unique token
    token = str(uuid.uuid4())
    
    # Set expiration for 1 hour from now
    expiration = datetime.utcnow() + timedelta(hours=1)
    
    # Apply to the user/admin object
    user_or_admin.reset_token = token
    user_or_admin.token_expiration = expiration
    try:
        db.session.commit()
        return token
    except Exception as e:
        db.session.rollback()
        logging.error(f"Failed to commit reset token: {e}")
        return None


# --- Database Models ---

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    marital_status = db.Column(db.String(50), nullable=False)
    state_of_origin = db.Column(db.String(100), nullable=False)
    lga = db.Column(db.String(100), nullable=False)
    residential_address = db.Column(db.String(200), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile_picture = db.Column(db.String(200), nullable=True, default='default.png')
    last_login_ip = db.Column(db.String(45), nullable=True)
    last_login_at = db.Column(db.DateTime, nullable=True, default=datetime.utcnow)
    
    # NEW: Password Reset Fields
    reset_token = db.Column(db.String(100), nullable=True, unique=True)
    token_expiration = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"User('{self.email}', '{self.full_name}')"

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    
    # NEW: Password Reset Fields
    reset_token = db.Column(db.String(100), nullable=True, unique=True)
    token_expiration = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

    @property
    def is_active(self):
        return True 

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def __repr__(self):
        return f'<Admin {self.username}>'

# Decorator to ensure only authenticated admins can access a route
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not isinstance(current_user, Admin):
            flash('You must be logged in as an administrator to access this page.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Remaining Database Models (kept for completeness) ---

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    description = db.Column(db.Text, nullable=True)
    user = db.relationship('User', backref=db.backref('activities', lazy=True))
    def __repr__(self):
        return f"Activity('{self.user_id}', '{self.activity_type}', '{self.timestamp}')"

class Cycle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    period_length = db.Column(db.Integer, nullable=True)
    cycle_length = db.Column(db.Integer, nullable=True)
    user = db.relationship('User', backref=db.backref('cycles', lazy=True))
    def __repr__(self):
        return f"Cycle(User:{self.user_id}, Start:{self.start_date}, End:{self.end_date})"

class SymptomLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    log_date = db.Column(db.Date, nullable=False, default=date.today)
    symptoms = db.Column(db.Text, nullable=True)
    mood = db.Column(db.String(50), nullable=True)
    flow = db.Column(db.String(50), nullable=True)
    pain_level = db.Column(db.Integer, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    user = db.relationship('User', backref=db.backref('symptom_logs', lazy=True))
    def __repr__(self):
        return f"SymptomLog(User:{self.user_id}, Date:{self.log_date})"

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    image_filename = db.Column(db.String(200), nullable=True)
    video_filename = db.Column(db.String(200), nullable=True)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    author = db.relationship('User', backref=db.backref('posts', lazy=True))
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")
    def __repr__(self):
        return f"BlogPost('{self.title}', '{self.date_posted}')"

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    author = db.relationship('User', backref=db.backref('comments', lazy=True))
    replies = db.relationship('Reply', backref='comment', lazy=True, cascade="all, delete-orphan")
    def __repr__(self):
        return f"Comment('{self.content}', '{self.date_posted}')"

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    author = db.relationship('User', backref=db.backref('replies', lazy=True))
    def __repr__(self):
        return f"Reply('{self.content}', '{self.date_posted}')"

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    def __repr__(self):
        return f"Contact('{self.name}', '{self.email}', '{self.subject}')"

class SuccessStory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    author = db.relationship('User', backref=db.backref('success_stories', lazy=True))
    def __repr__(self):
        return f"SuccessStory('{self.title}', '{self.date_posted}')"

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    admin = db.relationship('Admin', backref=db.backref('announcements', lazy=True))
    def __repr__(self):
        return f"Announcement('{self.title}', '{self.date_posted}')"

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    admin = db.relationship('Admin', backref=db.backref('events', lazy=True))
    media = db.relationship('EventMedia', backref='event', lazy=True, cascade="all, delete-orphan")
    def __repr__(self):
        return f"Event('{self.title}', '{self.event_date}', '{self.location}')"

class EventMedia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    file_type = db.Column(db.String(20), nullable=False)
    def __repr__(self):
        return f"EventMedia('{self.filename}', Type:'{self.file_type}')"


# --- Email Sending Function (From original user context) ---
def send_email(to_email, subject, body):
    sender_email = os.environ.get('EMAIL_USER', 'riarhubnigeria@gmail.com')
    sender_password = os.environ.get('EMAIL_PASS', 'qjju lypl enik damd') # NOTE: This should be an App Password
    smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))

    if not sender_email or not sender_password:
        logging.error("Email credentials not set. Cannot send email.")
        return False

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        logging.info(f"Email sent to {to_email} for subject: {subject}")
        return True
    except Exception as e:
        logging.error(f"Failed to send email to {to_email}: {e}")
        return False


# --- FORGOTTEN PASSWORD ROUTES (New Functionality) ---

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Handles the request to start the password reset process,
    sending a time-limited token via email.
    """
    if request.method == 'POST':
        email = request.form.get('email')
        user_type = request.form.get('user_type') 
        
        target = None
        target_model_name = ""

        if user_type == 'user':
            target = User.query.filter_by(email=email).first()
            target_model_name = "user"
        elif user_type == 'admin':
            target = Admin.query.filter_by(email=email).first()
            target_model_name = "admin"
        
        if target:
            token = generate_reset_token(target)
            
            if token:
                # IMPORTANT: Use _external=True to generate a full, clickable URL
                reset_url = url_for('set_new_password', token=token, user_type=target_model_name, _external=True)
                
                subject = f"Password Reset Request for your {target_model_name.title()} Account"
                body = f"""
Hello,

You have requested a password reset for your {target_model_name} account ({email}).

Please click the following link to reset your password:
{reset_url}

This link is valid for 1 hour. If you did not request this, please ignore this email.

Thanks,
The ROAR Team
"""
                if send_email(email, subject, body):
                    flash('A password reset link has been sent to your email. Please check your inbox.', 'success')
                else:
                    flash('Failed to send password reset email. Please try again later.', 'danger')
            else:
                flash('An error occurred during token generation. Please try again.', 'danger')
        else:
            # Generic message for security
            flash('If an account with that email and type exists, a password reset link has been sent.', 'info')
            
        return redirect(url_for('forgot_password'))
        
    return render_template('forgot_password.html')

@app.route('/reset_password/<user_type>/<token>', methods=['GET', 'POST'])
def set_new_password(user_type, token):
    """
    Validates the token and processes the form submission to set the new password.
    """
    
    target_model = User if user_type == 'user' else Admin
    target = target_model.query.filter_by(reset_token=token).first()

    # 1. Token Validation Check
    if not target or target.token_expiration < datetime.utcnow():
        flash('Invalid or expired password reset link. Please request a new one.', 'danger')
        # Clear token if expired but found
        if target and target.token_expiration < datetime.utcnow():
            target.reset_token = None
            target.token_expiration = None
            db.session.commit()
        return redirect(url_for('forgot_password'))
        
    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('set_new_password.html', token=token, user_type=user_type)
            
        # 2. Hash and set the new password
        try:
            if user_type == 'user':
                target.password = generate_password_hash(new_password)
            else: # admin
                target.set_password(new_password) 
                
            # 3. Clear the token fields after successful reset
            target.reset_token = None
            target.token_expiration = None
            db.session.commit()
            
            flash('Your password has been successfully reset! You can now log in.', 'success')
            
            login_route = 'admin_login' if user_type == 'admin' else 'login'
            # Assuming 'login' and 'admin_login' routes exist
            return redirect(url_for(login_route))
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error resetting password: {e}")
            flash('An internal error occurred while resetting the password.', 'danger')
            
    # GET request: Show the form to set a new password
    return render_template('set_new_password.html', token=token, user_type=user_type)

@app.route('/')
def home():
    """
    Home page route. Fetches the latest 3 success stories/events to display.
    """
    # Fetch the 3 most recent events, ordered by event_date (descending)
    # If the Event model doesn't have an 'event_date', use a 'created_at' field instead.
    latest_events = Event.query.order_by(Event.event_date.desc()).limit(3).all()
    
    # Passing the limited list and the current time (for 'Upcoming' check) to the home template
    return render_template('index.html', latest_events=latest_events, now=datetime.now())


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('fullName')
        email = request.form.get('email')
        phone_number = request.form.get('phoneNumber')
        date_of_birth_str = request.form.get('dob')
        marital_status = request.form.get('maritalStatus')
        state_of_origin = request.form.get('stateOfOrigin')
        lga = request.form.get('lga')
        residential_address = request.form.get('resiAddress')
        password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')
        ip_address = request.remote_addr
        profile_picture_filename = 'default.png'

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            logging.warning(f"Signup failed for {email} (IP: {ip_address}): Passwords mismatch.")
            return redirect(url_for('signup'))

        existing_user_email = User.query.filter_by(email=email).first()
        existing_user_phone = User.query.filter_by(phone_number=phone_number).first()

        if existing_user_email:
            flash('Email address already registered.', 'danger')
            logging.warning(f"Signup failed for {email} (IP: {ip_address}): Email already exists.")
            return redirect(url_for('signup'))
        if existing_user_phone:
            flash('Phone number already registered.', 'danger')
            logging.warning(f"Signup failed for {email} (IP: {ip_address}): Phone number already exists.")
            return redirect(url_for('signup'))

        if 'profilePicture' in request.files:
            file = request.files['profilePicture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = str(uuid.uuid4()) + os.path.splitext(filename)[1]
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                profile_picture_filename = unique_filename
            else:
                flash('Invalid file type for profile picture. Allowed types: png, jpg, jpeg, gif.', 'warning')
                logging.warning(f"Signup for {email} (IP: {ip_address}): Invalid profile picture file type.")

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date()

            new_user = User(
                full_name=full_name,
                email=email,
                phone_number=phone_number,
                date_of_birth=date_of_birth,
                marital_status=marital_status,
                state_of_origin=state_of_origin,
                lga=lga,
                residential_address=residential_address,
                password=hashed_password,
                profile_picture=profile_picture_filename,
                last_login_ip=ip_address,
                last_login_at=datetime.utcnow()
            )
            db.session.add(new_user)
            db.session.commit()

            activity = UserActivity(
                user_id=new_user.id,
                activity_type='signup',
                ip_address=ip_address,
                description=f"User {new_user.email} successfully signed up."
            )
            db.session.add(activity)
            db.session.commit()
            logging.info(f"User {new_user.email} (ID: {new_user.id}) signed up from IP: {ip_address}")

            welcome_subject = "Welcome to ROAR NIGERIA!"
            welcome_body = f"Dear {full_name},\n\nWelcome to ROAR NIGERIA ! We're thrilled to have you join our community of incubating startups.\n\nBest regards,\nThe ROAR NIGERIA Team"
            send_email(email, welcome_subject, welcome_body)

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during signup: {e}', 'danger')
            logging.error(f"Signup error for {email} (IP: {ip_address}): {e}")
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If a regular user is already authenticated, redirect to their dashboard
    if current_user.is_authenticated and isinstance(current_user, User):
        return redirect(url_for('dashboard'))

    # If an admin is logged in and tries to access regular user login, redirect them
    if current_user.is_authenticated and isinstance(current_user, Admin):
        flash("You are already logged in as an Admin.", "info")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        ip_address = request.remote_addr

        user = User.query.filter((User.email == identifier) | (User.phone_number == identifier)).first()

        if user and check_password_hash(user.password, password):
            login_user(user) # Log in the regular user
            
            user.last_login_ip = ip_address
            user.last_login_at = datetime.utcnow()
            db.session.commit()

            activity = UserActivity(
                user_id=user.id,
                activity_type='login',
                ip_address=ip_address,
                description=f"User {user.email} successfully logged in."
            )
            db.session.add(activity)
            db.session.commit()
            logging.info(f"User {user.email} (ID: {user.id}) logged in from IP: {ip_address}")

            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email/phone and password', 'danger')
            logging.warning(f"Failed login attempt for identifier: {identifier} from IP: {ip_address}")

    return render_template('login.html')

# --- Menstrual Health Tracking Routes ---
@app.route('/log_period', methods=['GET', 'POST'])
@login_required
def log_period():
    if request.method == 'POST':
        start_date_str = request.form.get('startDate')
        end_date_str = request.form.get('endDate')
        
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

            if start_date > end_date:
                flash('End date cannot be before start date.', 'danger')
                return redirect(url_for('log_period'))

            period_length = (end_date - start_date).days + 1

            last_cycle = Cycle.query.filter_by(user_id=current_user.id)\
                                   .order_by(Cycle.start_date.desc()).first()
            
            new_cycle = Cycle(
                user_id=current_user.id,
                start_date=start_date,
                end_date=end_date,
                period_length=period_length
            )
            db.session.add(new_cycle)
            db.session.commit()

            if last_cycle and last_cycle.cycle_length is None: # Only update if not already set
                # Calculate cycle length from the start of the previous period to the start of the current one
                last_cycle.cycle_length = (new_cycle.start_date - last_cycle.start_date).days
                db.session.commit()


            activity = UserActivity(
                user_id=current_user.id,
                activity_type='log_period',
                ip_address=request.remote_addr,
                description=f"Logged period from {start_date} to {end_date} (Length: {period_length} days)."
            )
            db.session.add(activity)
            db.session.commit()

            flash('Period logged successfully!', 'success')
            return redirect(url_for('dashboard'))

        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'danger')
            return redirect(url_for('log_period'))
        except Exception as e:
            db.session.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
            logging.error(f"Error logging period for user {current_user.email}: {e}")
            return redirect(url_for('log_period'))

    return render_template('log_period.html')

@app.route('/log_symptoms', methods=['GET', 'POST'])
@login_required
def log_symptoms():
    if request.method == 'POST':
        log_date_str = request.form.get('logDate')
        mood = request.form.get('mood')
        flow = request.form.get('flow')
        pain_level = request.form.get('painLevel')
        notes = request.form.get('notes')

        try:
            log_date = datetime.strptime(log_date_str, '%Y-%m-%d').date()
            
            new_log = SymptomLog(
                user_id=current_user.id,
                log_date=log_date,
                symptoms=notes, # Assuming 'symptoms' field holds the notes/detailed symptoms
                mood=mood,
                flow=flow,
                pain_level=int(pain_level) if pain_level else None,
                notes=notes
            )
            db.session.add(new_log)
            db.session.commit()

            activity = UserActivity(
                user_id=current_user.id,
                activity_type='log_symptoms',
                ip_address=request.remote_addr,
                description=f"Logged symptoms for {log_date} (Mood: {mood}, Flow: {flow})."
            )
            db.session.add(activity)
            db.session.commit()

            flash('Symptoms logged successfully!', 'success')
            return redirect(url_for('dashboard'))

        except ValueError:
            flash('Invalid date or pain level format.', 'danger')
            return redirect(url_for('log_symptoms'))
        except Exception as e:
            db.session.rollback()
            flash(f'An unexpected error occurred: {e}', 'danger')
            logging.error(f"Error logging symptoms for user {current_user.email}: {e}")
            return redirect(url_for('log_symptoms'))

    return render_template('log_symptoms.html', today_date=date.today().isoformat())

# --- Prediction Logic ---
def get_cycle_predictions(user_id):
    cycles = Cycle.query.filter_by(user_id=user_id)\
                             .filter(Cycle.cycle_length.isnot(None))\
                             .order_by(Cycle.start_date.desc())\
                             .limit(6).all()

    if not cycles or len(cycles) < 2:
        return {
            'next_period_start': None,
            'ovulation_day': None,
            'fertile_window_start': None,
            'fertile_window_end': None,
            'message': 'Log at least two periods to get predictions.'
        }

    total_cycle_length = sum(c.cycle_length for c in cycles)
    avg_cycle_length = round(total_cycle_length / len(cycles))

    last_period = Cycle.query.filter_by(user_id=user_id)\
                              .order_by(Cycle.start_date.desc()).first()
    
    if not last_period:
        return {
            'next_period_start': None,
            'ovulation_day': None,
            'fertile_window_start': None,
            'fertile_window_end': None,
            'message': 'No recent period found for prediction calculation.'
        }

    last_period_start = last_period.start_date
    next_period_start = last_period_start + timedelta(days=avg_cycle_length)
    ovulation_day = next_period_start - timedelta(days=14)
    fertile_window_start = ovulation_day - timedelta(days=5)
    fertile_window_end = ovulation_day + timedelta(days=1)

    return {
        'next_period_start': next_period_start,
        'ovulation_day': ovulation_day,
        'fertile_window_start': fertile_window_start,
        'fertile_window_end': fertile_window_end,
        'avg_cycle_length': avg_cycle_length,
        'message': 'Predictions based on your average cycle length.'
    }


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # 1. Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        # 2. Server-side validation
        if not all([name, email, subject, message]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('contact'))

        if '@' not in email or '.' not in email:
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('contact'))
            
        try:
            # 3. Create a new Contact object and save it to the database
            new_contact = Contact(
                name=name,
                email=email,
                subject=subject,
                message=message
            )
            db.session.add(new_contact)
            db.session.commit()
            
            # 4. Prepare and send the email notification
            email_body = f"You have received a new message from the contact form.\n\n" \
                         f"Name: {name}\n" \
                         f"Email: {email}\n" \
                         f"Subject: {subject}\n" \
                         f"Message:\n{message}"

            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@thegutsywoman.com')
            send_email(admin_email, f"New Contact Message: {subject}", email_body)
            
            # 5. Flash a success message
            flash('Thank you for your message! We will get back to you shortly.', 'success')
            logging.info(f"Contact form submitted by {email}. Data saved and email notification sent.")
            return redirect(url_for('contact'))

        except Exception as e:
            # Handle any database or email-sending errors
            db.session.rollback()
            flash('There was an issue processing your message. Please try again later.', 'danger')
            logging.error(f"Error processing contact form from {email}: {e}")
            return redirect(url_for('contact'))

    return render_template('contact.html')


@app.route('/dashboard')
@login_required
def dashboard():
    # This route is for regular users, protected by Flask-Login for User model.
    # If an Admin somehow gets here, redirect to admin dashboard.
    if isinstance(current_user, Admin):
        return redirect(url_for('admin_dashboard'))

    user_activities = UserActivity.query.filter_by(user_id=current_user.id)\
                                         .order_by(UserActivity.timestamp.desc())\
                                         .limit(10).all()
    
    predictions = get_cycle_predictions(current_user.id) 

    cycle_history = Cycle.query.filter_by(user_id=current_user.id)\
                               .order_by(Cycle.start_date.desc())\
                               .limit(5).all()
    
    # NEW: Fetch latest announcements for the dashboard
    latest_announcements = Announcement.query.order_by(Announcement.date_posted.desc()).limit(3).all()

    # --- Birthday Logic ---
    today = date.today()
    is_birthday = False
    age = None

    if current_user.date_of_birth:
        if current_user.date_of_birth.month == today.month and \
           current_user.date_of_birth.day == today.day:
            is_birthday = True
            # Calculate age
            age = today.year - current_user.date_of_birth.year
            # Adjust age if birthday hasn't occurred yet this year (shouldn't happen if month/day match)
            # This check is usually for when you calculate age for any given date, but kept for robustness.
            if (today.month, today.day) < (current_user.date_of_birth.month, current_user.date_of_birth.day):
                age -= 1
    # --- End Birthday Logic ---


    return render_template('dashboard.html', 
                           user=current_user, 
                           activities=user_activities,
                           predictions=predictions,
                           cycle_history=cycle_history,
                           announcements=latest_announcements,
                           is_birthday=is_birthday, # Pass birthday flag
                           age=age) # Pass age




# NEW: User Courses Route
@app.route('/courses')
def user_courses():
    """
    User-facing route to display a list of available courses.
    """
    # For now, this is a static page listing, no database query needed.
    return render_template('user_courses.html')


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = current_user

    if request.method == 'POST':
        user.full_name = request.form.get('fullName')
        user.email = request.form.get('email')
        user.phone_number = request.form.get('phoneNumber')
        user.marital_status = request.form.get('maritalStatus')
        user.state_of_origin = request.form.get('stateOfOrigin')
        user.lga = request.form.get('lga')
        user.residential_address = request.form.get('resiAddress')
        
        date_of_birth_str = request.form.get('dob')
        if date_of_birth_str:
            try:
                user.date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid date of birth format.', 'danger')
                return redirect(url_for('edit_profile'))

        if 'profilePicture' in request.files:
            file = request.files['profilePicture']
            if file and allowed_file(file.filename):
                if user.profile_picture and user.profile_picture != 'default.png':
                    old_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_picture)
                    if os.path.exists(old_pic_path):
                        os.remove(old_pic_path)
                        logging.info(f"Old profile picture {old_pic_path} removed for user {user.email}.")

                filename = secure_filename(file.filename)
                unique_filename = str(uuid.uuid4()) + os.path.splitext(filename)[1]
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                user.profile_picture = unique_filename
                logging.info(f"User {user.email} updated profile picture to {unique_filename}.")
            elif file.filename == '':
                pass
            else:
                flash('Invalid file type for profile picture. Allowed types: png, jpg, jpeg, gif.', 'warning')
                logging.warning(f"Profile update for {user.email} (IP: {request.remote_addr}): Invalid profile picture file type.")

        new_password = request.form.get('newPassword')
        confirm_new_password = request.form.get('confirmNewPassword')

        if new_password:
            if new_password != confirm_new_password:
                flash('New passwords do not match!', 'danger')
                logging.warning(f"Password change failed for {user.email} (IP: {request.remote_addr}): New passwords mismatch.")
                return redirect(url_for('edit_profile'))
            else:
                user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                flash('Password updated successfully!', 'success')
                logging.info(f"User {user.email} changed password from IP: {request.remote_addr}.")
                change_subject = "Your Gutsy Woman Network Password Has Been Changed"
                change_body = f"Dear {user.full_name},\n\nYour password for The Gutsy Woman Network account has been successfully changed.\n\nIf you did not make this change, please contact us immediately.\n\nBest regards,\nThe Gutsy Woman Team"
                send_email(user.email, change_subject, change_body)

        try:
            db.session.commit()
            activity = UserActivity(
                user_id=user.id,
                activity_type='profile_update',
                ip_address=request.remote_addr,
                description=f"User {user.email} updated their profile."
            )
            db.session.add(activity)
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during profile update: {e}', 'danger')
            logging.error(f"Profile update error for {user.email} (IP: {request.remote_addr}): {e}")
            return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', user=user)

@app.route('/logout')
@login_required
def logout():
    # This logout handles both regular users and admins
    user_id = current_user.id
    user_email = current_user.email if isinstance(current_user, User) else current_user.username
    user_type = "User" if isinstance(current_user, User) else "Admin"

    activity = UserActivity(
        user_id=user_id,
        activity_type='logout',
        ip_address=request.remote_addr,
        description=f"{user_type} {user_email} logged out."
    )
    db.session.add(activity)
    db.session.commit()
    logging.info(f"{user_type} {user_email} (ID: {user_id}) logged out from IP: {request.remote_addr}")
    logout_user()
    # Manual session pop for admin_id if it exists, to be consistent with new checks
    session.pop('admin_id', None) 
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# --- NEW: Admin Login Route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    # If an admin is already logged in, redirect them to the admin dashboard.
    if current_user.is_authenticated and isinstance(current_user, Admin):
        flash("You are already logged in as an Admin.", "info")
        return redirect(url_for('admin_dashboard'))

    # If a regular user is logged in and tries to access admin login, log them out first.
    if current_user.is_authenticated and isinstance(current_user, User):
        logout_user()
        flash("Logged out from regular user account to access admin login.", "info")

    if request.method == 'POST':
        # Use .get() to safely retrieve form data, returning None if the key is not found.
        email = request.form.get('email')
        password = request.form.get('password')

        # Perform server-side validation for missing fields
        if not email:
            flash('Email field cannot be empty.', 'danger')
            return render_template('admin_login.html')
        if not password:
            flash('Password field cannot be empty.', 'danger')
            return render_template('admin_login.html')

        admin = Admin.query.filter_by(email=email).first()

        if admin and admin.check_password(password):
            login_user(admin)  # Log in the admin user
            # Explicitly set admin_id in session for manual checks
            session['admin_id'] = admin.id
            flash('Logged in as Admin successfully.', 'success')
            # Redirect to the dashboard or to the page they tried to access
            next_page = request.args.get('next')
            return redirect(next_page or url_for('admin_dashboard'))
        else:
            flash('Admin Login Unsuccessful. Please check email and password', 'danger')
    
    # For GET requests or failed POST attempts, render the login page.
    return render_template('admin_login.html')

# Admin registration route
@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        # Check if the maximum number of admins is reached
        if Admin.query.count() >= 2:
            flash("Only two admins are allowed.", "danger") 
            return redirect(url_for('admin_register'))

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if the email already exists before attempting to add
        existing_admin = Admin.query.filter_by(email=email).first()
        if existing_admin:
            flash("An account with this email already exists. Please use a different email or log in.", "warning")
            return redirect(url_for('admin_register'))
        else:
            # Create the new admin object
            admin = Admin(username=username, email=email)
            admin.set_password(password) # Assuming set_password hashes the password

            db.session.add(admin)
            try:
                db.session.commit()
                flash("Admin registered successfully.", "success")
                return redirect(url_for('admin_login'))
            except IntegrityError:
                # This block would catch any other unexpected integrity errors,
                # though the email check above should prevent the common one.
                db.session.rollback()
                flash("An unexpected error occurred during registration. Please try again.", "danger")
                return redirect(url_for('admin_register'))

    return render_template('admin_register.html')


# --- Blog Routes ---
@app.route('/blog')
def blog():
    # Only retrieve approved blog posts for display on the main blog page
    posts = BlogPost.query.filter_by(is_approved=True).order_by(BlogPost.date_posted.desc()).all()
    return render_template('blog.html', posts=posts)

@app.route('/post/<int:post_id>')
def single_post(post_id):
    post = BlogPost.query.get_or_404(post_id)
    # Ensure only approved posts can be viewed directly unless the user is an admin
    if not post.is_approved and not (current_user.is_authenticated and isinstance(current_user, Admin)):
        abort(404) # Or redirect to a 'pending review' page
    return render_template('single_post.html', post=post)
@app.route('/create_blog_post', methods=['GET', 'POST'])
@login_required
def create_blog_post():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        image_file = request.files.get('image')
        video_file = request.files.get('video')

        if not title or not content:
            flash('Title and content are required for a blog post.', 'danger')
            return redirect(url_for('create_blog_post'))

        image_filename = None
        video_filename = None

        if image_file and allowed_blog_image_file(image_file.filename):
            filename = str(uuid.uuid4()) + os.path.splitext(secure_filename(image_file.filename))[1]
            file_path = os.path.join(app.config['UPLOAD_BLOG_FOLDER'], filename)
            # Corrected line: Use image_file.save()
            image_file.save(file_path)
            image_filename = filename
        elif image_file and image_file.filename != '':
            flash('Invalid image file type. Allowed: png, jpg, jpeg, gif.', 'warning')
            return redirect(url_for('create_blog_post'))

        if video_file and allowed_blog_video_file(video_file.filename):
            filename = str(uuid.uuid4()) + os.path.splitext(secure_filename(video_file.filename))[1]
            file_path = os.path.join(app.config['UPLOAD_BLOG_FOLDER'], filename)
            # Corrected line: Use video_file.save()
            video_file.save(file_path)
            video_filename = filename
        elif video_file and video_file.filename != '':
            flash('Invalid video file type. Allowed: mp4, webm, ogg.', 'warning')
            return redirect(url_for('create_blog_post'))
        
        # Only one media file is allowed (optional logic, remove if both are fine)
        if image_filename and video_filename:
            flash('Only one media file (image or video) is allowed per post. Please choose one.', 'warning')
            # Clean up the saved files if both were uploaded
            if os.path.exists(os.path.join(app.config['UPLOAD_BLOG_FOLDER'], image_filename)):
                os.remove(os.path.join(app.config['UPLOAD_BLOG_FOLDER'], image_filename))
            if os.path.exists(os.path.join(app.config['UPLOAD_BLOG_FOLDER'], video_filename)):
                os.remove(os.path.join(app.config['UPLOAD_BLOG_FOLDER'], video_filename))
            return redirect(url_for('create_blog_post'))

        try:
            new_post = BlogPost(
                user_id=current_user.id,
                title=title,
                content=content,
                image_filename=image_filename,
                video_filename=video_filename,
                is_approved=False # Posts need admin approval
            )
            db.session.add(new_post)
            db.session.commit()

            activity = UserActivity(
                user_id=current_user.id,
                activity_type='create_blog_post',
                ip_address=request.remote_addr,
                description=f"User {current_user.email} created blog post '{title}'."
            )
            db.session.add(activity)
            db.session.commit()

            flash('Your blog post has been submitted for review!', 'success')
            return redirect(url_for('blog'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while submitting your blog post: {e}', 'danger')
            logging.error(f"Error creating blog post for user {current_user.email}: {e}")
            # Clean up uploaded files if an error occurs after saving to disk
            if image_filename and os.path.exists(os.path.join(app.config['UPLOAD_BLOG_FOLDER'], image_filename)):
                os.remove(os.path.join(app.config['UPLOAD_BLOG_FOLDER'], image_filename))
            if video_filename and os.path.exists(os.path.join(app.config['UPLOAD_BLOG_FOLDER'], video_filename)):
                os.remove(os.path.join(app.config['UPLOAD_BLOG_FOLDER'], video_filename))
            return redirect(url_for('create_blog_post'))

    return render_template('create_blog_post.html')
@app.route('/add_comment/<int:post_id>', methods=['POST'])
@login_required
def add_comment(post_id):
    post = BlogPost.query.get_or_404(post_id)
    content = request.form.get('content')

    if not content:
        flash('Comment cannot be empty.', 'danger')
        return redirect(url_for('single_post', post_id=post.id))

    try:
        new_comment = Comment(
            post_id=post.id,
            user_id=current_user.id,
            content=content
        )
        db.session.add(new_comment)
        db.session.commit()

        activity = UserActivity(
            user_id=current_user.id,
            activity_type='add_comment',
            ip_address=request.remote_addr,
            description=f"User {current_user.email} commented on post '{post.title}'."
        )
        db.session.add(activity)
        db.session.commit()

        flash('Your comment has been added!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while adding your comment: {e}', 'danger')
        logging.error(f"Error adding comment by user {current_user.email} on post {post_id}: {e}")
    
    return redirect(url_for('single_post', post_id=post.id))

# Admin management routes for blog posts
@app.route('/admin/blog')
def admin_manage_blog():
    # Manual session check for admin
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))

    all_posts = BlogPost.query.order_by(BlogPost.date_posted.desc()).all()
    pending_posts = BlogPost.query.filter_by(is_approved=False).order_by(BlogPost.date_posted.asc()).all()
    return render_template('admin_manage_blog.html', all_posts=all_posts, pending_posts=pending_posts)

@app.route('/admin/blog/approve/<int:post_id>')
def admin_approve_post(post_id):
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    post = BlogPost.query.get_or_404(post_id)
    post.is_approved = True
    try:
        db.session.commit()
        flash(f'Blog post "{post.title}" approved.', 'success')
        # Using session['admin_id'] for logging consistency with manual session checks
        logging.info(f"Admin (ID: {session.get('admin_id')}) approved blog post ID: {post_id}")
    except Exception as e:
        db.session.rollback()
        flash(f'Error approving post: {e}', 'danger')
        logging.error(f"Admin (ID: {session.get('admin_id')}) failed to approve blog post ID: {post_id}: {e}")
    return redirect(url_for('admin_manage_blog'))

@app.route('/admin/blog/delete/<int:post_id>')
def admin_delete_post(post_id):
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    post = BlogPost.query.get_or_404(post_id)
    try:
        # Delete associated media files if they exist
        if post.image_filename:
            image_path = os.path.join(app.config['UPLOAD_BLOG_FOLDER'], post.image_filename)
            if os.path.exists(image_path):
                os.remove(image_path)
                logging.info(f"Deleted blog image file: {image_path}")
        if post.video_filename:
            video_path = os.path.join(app.config['UPLOAD_BLOG_FOLDER'], post.video_filename)
            if os.path.exists(video_path):
                os.remove(video_path)
                logging.info(f"Deleted blog video file: {video_path}")

        db.session.delete(post)
        db.session.commit()
        flash(f'Blog post "{post.title}" and its associated comments/replies deleted.', 'success')
        # Using session['admin_id'] for logging consistency with manual session checks
        logging.info(f"Admin (ID: {session.get('admin_id')}) deleted blog post ID: {post_id}")
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting post: {e}', 'danger')
        logging.error(f"Admin (ID: {session.get('admin_id')}) failed to delete blog post ID: {post_id}: {e}")
    return redirect(url_for('admin_manage_blog'))


# --- Success Stories Routes ---
@app.route('/success_stories')
def success_stories():
    """
    Renders the success stories page, displaying all approved success stories.
    Fetches stories from the database that have been marked as approved.
    """
    # Query the database to get all success stories that are approved,
    # ordered by the most recently posted first.
    stories = SuccessStory.query.filter_by(is_approved=True).order_by(SuccessStory.date_posted.desc()).all()
    # Render the 'success_stories.html' template, passing the fetched stories to it.
    return render_template('success_stories.html', stories=stories)

@app.route('/share_success_story', methods=['GET', 'POST'])
@login_required
def share_success_story():
    """
    Handles sharing a new success story.
    Allows logged-in users to submit a story, which requires admin approval.
    """
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')

        if not all([title, content]):
            flash('Both title and content are required to share your story.', 'danger')
            return redirect(url_for('share_success_story'))
        
        try:
            new_story = SuccessStory(
                user_id=current_user.id,
                title=title,
                content=content,
                is_approved=False # Stories need admin approval
            )
            db.session.add(new_story)
            db.session.commit()

            # Log user activity for submitting a story
            activity = UserActivity(
                user_id=current_user.id,
                activity_type='share_story',
                ip_address=request.remote_addr,
                description=f"User {current_user.email} submitted a success story titled '{title}' for approval."
            )
            db.session.add(activity)
            db.session.commit()

            flash('Your success story has been submitted for review!', 'success')
            return redirect(url_for('success_stories'))

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while submitting your story: {e}', 'danger')
            logging.error(f"Error sharing success story for user {current_user.email}: {e}")
            return redirect(url_for('share_success_story'))

    # For GET request, render the form to share a story
    return render_template('share_success_story.html')

# Admin management routes for success stories
@app.route('/admin/stories')
def admin_manage_stories():
    # Manual session check for admin
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to manage all success stories, both pending and approved.
    Requires admin privileges.
    """
    all_stories = SuccessStory.query.order_by(SuccessStory.date_posted.desc()).all()
    pending_stories = SuccessStory.query.filter_by(is_approved=False).order_by(SuccessStory.date_posted.asc()).all()
    return render_template('admin_manage_stories.html', all_stories=all_stories, pending_stories=pending_stories)

@app.route('/admin/stories/approve/<int:story_id>')
def admin_approve_story(story_id):
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to approve a specific success story.
    """
    story = SuccessStory.query.get_or_404(story_id)
    story.is_approved = True
    try:
        db.session.commit()
        flash(f'Success story "{story.title}" approved.', 'success')
        # Using session['admin_id'] for logging consistency with manual session checks
        logging.info(f"Admin (ID: {session.get('admin_id')}) approved success story ID: {story_id}")
    except Exception as e:
        db.session.rollback()
        flash(f'Error approving story: {e}', 'danger')
        logging.error(f"Admin (ID: {session.get('admin_id')}) failed to approve success story ID: {story_id}: {e}")
    return redirect(url_for('admin_manage_stories'))

@app.route('/admin/stories/delete/<int:story_id>')
def admin_delete_story(story_id):
    # Manual session check for admin
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    """
    Admin route to delete a specific success story.
    """
    story = SuccessStory.query.get_or_404(story_id)
    try:
        db.session.delete(story)
        db.session.commit()
        flash(f'Success story "{story.title}" deleted.', 'success')
        # Using session['admin_id'] for logging consistency with manual session checks
        logging.info(f"Admin (ID: {session.get('admin_id')}) deleted success story ID: {story_id}")
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting story: {e}', 'danger')
        logging.error(f"Admin (ID: {session.get('admin_id')}) failed to delete success story ID: {story_id}: {e}")
    return redirect(url_for('admin_manage_stories'))

# Admin Dashboard Route
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    # Count pending blog posts and success stories for the dashboard summary
    pending_posts_count = BlogPost.query.filter_by(is_approved=False).count()
    pending_stories_count = SuccessStory.query.filter_by(is_approved=False).count()
    new_contacts_count = Contact.query.count() # Or filter by unread/new if you add a status field

    return render_template('admin_dashboard.html',
                           pending_posts_count=pending_posts_count,
                           pending_stories_count=pending_stories_count,
                           new_contacts_count=new_contacts_count)

# Admin view contact messages
@app.route('/admin/contacts')
def admin_view_contacts():
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    contacts = Contact.query.order_by(Contact.timestamp.desc()).all()
    return render_template('admin_view_contacts.html', contacts=contacts)

# NEW: Admin Post Announcement Route
@app.route('/admin/announcements/new', methods=['GET', 'POST'])
def admin_post_announcement():
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    # Fetch all announcements to display them on the page
    all_announcements = Announcement.query.order_by(Announcement.date_posted.desc()).all()

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')

        if not title or not content:
            flash('Title and content are required for an announcement.', 'danger')
            return redirect(url_for('admin_post_announcement'))
        
        try:
            # current_user is already available due to @admin_required
            new_announcement = Announcement(
                admin_id=current_user.id,
                title=title,
                content=content
            )
            db.session.add(new_announcement)
            db.session.commit()

            flash('Announcement posted successfully!', 'success')
            # Redirect to the same page to show the updated list
            return redirect(url_for('admin_post_announcement')) 

        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while posting the announcement: {e}', 'danger')
            logging.error(f"Error posting announcement by admin (ID: {current_user.id}): {e}")
            return redirect(url_for('admin_post_announcement'))

    return render_template('admin_post_announcement.html', announcements=all_announcements)

# NEW: Admin Delete Announcement Route
@app.route('/admin/announcements/delete/<int:announcement_id>')
def admin_delete_announcement(announcement_id):
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to delete a specific announcement.
    """
    announcement = Announcement.query.get_or_404(announcement_id)
    try:
        db.session.delete(announcement)
        db.session.commit()
        flash(f'Announcement "{announcement.title}" deleted successfully.', 'success')
        logging.info(f"Admin {current_user.username} deleted announcement: '{announcement.title}' (ID: {announcement_id})")
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting announcement: {e}', 'danger')
        logging.error(f"Admin {current_user.username} failed to delete announcement ID: {announcement_id}: {e}")
    return redirect(url_for('admin_post_announcement'))


# NEW: Route to display all announcements to users
@app.route('/announcements', methods=['GET'])
def announcements():
    """
    Displays a list of all announcements to general users, ordered by date.
    """
    all_announcements = Announcement.query.order_by(Announcement.date_posted.desc()).all()
    return render_template('user_announcements.html', announcements=all_announcements)

# NEW: Admin Event Management Routes
@app.route('/admin/events')
def admin_manage_events():
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to manage events (view all, add new, delete).
    """
    all_events = Event.query.order_by(Event.event_date.desc()).all()
    return render_template('admin_events.html', all_events=all_events)

@app.route('/admin/events/new', methods=['GET', 'POST'])
def admin_post_event():
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to post a new event, including multiple images and videos.
    """
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        event_date_str = request.form.get('eventDate')
        location = request.form.get('location')
        image_files = request.files.getlist('images') # Get list of image files
        video_files = request.files.getlist('videos') # Get list of video files

        if not all([title, description, event_date_str, location]):
            flash('All event fields (Title, Description, Event Date, Location) are required.', 'danger')
            return redirect(url_for('admin_post_event'))
        
        try:
            event_date = datetime.strptime(event_date_str, '%Y-%m-%d').date()
            
            new_event = Event(
                admin_id=current_user.id,
                title=title,
                description=description,
                event_date=event_date,
                location=location
            )
            db.session.add(new_event)
            db.session.flush() # Use flush to get the ID before commit for media saving

            # Save image files
            for img_file in image_files:
                if img_file and allowed_event_image_file(img_file.filename):
                    filename = str(uuid.uuid4()) + os.path.splitext(secure_filename(img_file.filename))[1]
                    file_path = os.path.join(app.config['UPLOAD_EVENT_FOLDER'], filename)
                    img_file.save(file_path)
                    new_media = EventMedia(event_id=new_event.id, filename=filename, file_type='image')
                    db.session.add(new_media)
                elif img_file and img_file.filename != '': # Handle invalid image files that were attempted to be uploaded
                    flash(f'Invalid image file type for {img_file.filename}. Allowed: png, jpg, jpeg, gif.', 'warning')
                    db.session.rollback() # Rollback event creation if media save fails
                    return redirect(url_for('admin_post_event'))

            # Save video files
            for vid_file in video_files:
                if vid_file and allowed_event_video_file(vid_file.filename):
                    filename = str(uuid.uuid4()) + os.path.splitext(secure_filename(vid_file.filename))[1]
                    file_path = os.path.join(app.config['UPLOAD_EVENT_FOLDER'], filename)
                    vid_file.save(file_path)
                    new_media = EventMedia(event_id=new_event.id, filename=filename, file_type='video')
                    db.session.add(new_media)
                elif vid_file and vid_file.filename != '': # Handle invalid video files that were attempted to be uploaded
                    flash(f'Invalid video file type for {vid_file.filename}. Allowed: mp4, webm, ogg.', 'warning')
                    db.session.rollback() # Rollback event creation if media save fails
                    return redirect(url_for('admin_post_event'))

            db.session.commit()
            flash('Event posted successfully!', 'success')
            # FIX: Changed current_user.username to current_user.email for logging
            logging.info(f"Admin {current_user.email} posted new event: '{title}'")
            return redirect(url_for('admin_manage_events'))

        except ValueError:
            db.session.rollback()
            flash('Invalid date format for Event Date. Please use YYYY-MM-DD.', 'danger')
            return redirect(url_for('admin_post_event'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while posting the event: {e}', 'danger')
            # FIX: Changed current_user.username to current_user.email for logging
            logging.error(f"Error posting event by admin {current_user.email}: {e}")
            return redirect(url_for('admin_post_event'))
    
    # For GET requests, render the event posting form
    return render_template('admin_post_event.html') # A separate form or integrated into admin_events.html

@app.route('/admin/events/delete/<int:event_id>')
def admin_delete_event(event_id):
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to delete an event and its associated media.
    """
    event = Event.query.get_or_404(event_id)
    try:
        # Delete associated media files from disk
        for media_item in event.media:
            file_path = os.path.join(app.config['UPLOAD_EVENT_FOLDER'], media_item.filename)
            if os.path.exists(file_path):
                os.remove(file_path)
                logging.info(f"Deleted event media file: {file_path}")
        
        db.session.delete(event)
        db.session.commit()
        flash(f'Event "{event.title}" and its media deleted successfully.', 'success')
        logging.info(f"Admin {current_user.username} deleted event: '{event.title}' (ID: {event_id})")
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting event: {e}', 'danger')
        logging.error(f"Admin {current_user.username} failed to delete event ID: {event_id}: {e}")
    return redirect(url_for('admin_manage_events'))


# NEW: Admin Manage Users Route
@app.route('/admin/users')
def admin_manage_users():
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to manage all registered user accounts.
    Requires admin privileges.
    """
    users = User.query.order_by(User.last_login_at.desc()).all()
    return render_template('admin_manage_users.html', users=users)


# NEW: Admin Edit User Route
@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to edit a user's information, including their password.
    """
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        # Update user details
        user.full_name = request.form.get('fullName')
        user.email = request.form.get('email')
        user.phone_number = request.form.get('phoneNumber')
        user.marital_status = request.form.get('maritalStatus')
        user.state_of_origin = request.form.get('stateOfOrigin')
        user.lga = request.form.get('lga')
        user.residential_address = request.form.get('resiAddress')
        
        date_of_birth_str = request.form.get('dob')
        if date_of_birth_str:
            try:
                user.date_of_birth = datetime.strptime(date_of_birth_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid date of birth format.', 'danger')
                return redirect(url_for('admin_edit_user', user_id=user.id))

        # Handle password change
        new_password = request.form.get('newPassword')
        confirm_new_password = request.form.get('confirmNewPassword')

        if new_password:
            if new_password != confirm_new_password:
                flash('New passwords do not match!', 'danger')
                return redirect(url_for('admin_edit_user', user_id=user.id))
            else:
                user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                flash('User password updated successfully!', 'success')
                logging.info(f"Admin {current_user.email} changed password for user ID: {user.id} ({user.email}).")
        
        try:
            db.session.commit()
            flash(f'User {user.full_name} updated successfully!', 'success')
            logging.info(f"Admin {current_user.email} updated user ID: {user.id} ({user.email}).")
            return redirect(url_for('admin_manage_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during user update: {e}', 'danger')
            logging.error(f"Error updating user ID: {user.id} by admin {current_user.email}: {e}")
            return redirect(url_for('admin_edit_user', user_id=user.id))

    return render_template('admin_edit_user.html', user=user)


# NEW: Admin Delete User Route
@app.route('/admin/users/delete/<int:user_id>')
def admin_delete_user(user_id):
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to delete a user account.
    This route should typically be accessed via a POST request from a form or JavaScript
    for safety, but a simple GET route is provided here for demonstration.
    Consider adding a confirmation dialog on the HTML page.
    """
    user_to_delete = User.query.get_or_404(user_id)

    try:
        # Delete user's profile picture if it's not the default
        if user_to_delete.profile_picture and user_to_delete.profile_picture != 'default.png':
            pic_path = os.path.join(app.config['UPLOAD_FOLDER'], user_to_delete.profile_picture)
            if os.path.exists(pic_path):
                os.remove(pic_path)
                logging.info(f"Deleted profile picture for user ID: {user_id} at {pic_path}")

        # Delete all associated data (cycles, symptom logs, blog posts, comments, etc.)
        # This requires `cascade="all, delete-orphan"` on relationships in models.
        # Ensure your models (User, Cycle, SymptomLog, BlogPost, Comment, Reply, SuccessStory, UserActivity)
        # have these cascade rules configured for proper cleanup.
        # For simplicity in this example, direct deletion is shown.
        # For a more robust solution, ensure your SQLAlchemy model relationships handle cascading deletes.
        
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'User {user_to_delete.full_name} ({user_to_delete.email}) deleted successfully.', 'success')
        logging.info(f"Admin {current_user.email} deleted user ID: {user_id} ({user_to_delete.email}).")
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {e}', 'danger')
        logging.error(f"Error deleting user ID: {user_id} by admin {current_user.email}: {e}")
    
    return redirect(url_for('admin_manage_users'))



# --- Admin Menstrual Health Management Routes ---

@app.route('/admin/menstrual_health')
def admin_manage_menstrual_health():
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to view and manage all menstrual cycle and symptom log data.
    Requires admin privileges.
    """
    # Fetch all cycles, ordered by start date (most recent first), including user details
    cycles = Cycle.query.order_by(Cycle.start_date.desc()).all()
    # Fetch all symptom logs, ordered by log date (most recent first), including user details
    symptom_logs = SymptomLog.query.order_by(SymptomLog.log_date.desc()).all()

    return render_template('admin_menstrual_health.html',
                           cycles=cycles,
                           symptom_logs=symptom_logs)

@app.route('/admin/menstrual_health/delete_cycle/<int:cycle_id>')
def admin_delete_cycle(cycle_id):
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to delete a specific menstrual cycle entry.
    """
    cycle_to_delete = Cycle.query.get_or_404(cycle_id)
    try:
        db.session.delete(cycle_to_delete)
        db.session.commit()
        flash(f'Cycle entry for user {cycle_to_delete.user.email} from {cycle_to_delete.start_date} deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting cycle entry: {e}', 'danger')
    return redirect(url_for('admin_manage_menstrual_health'))

@app.route('/admin/menstrual_health/delete_symptom_log/<int:log_id>')
def admin_delete_symptom_log(log_id):
    if 'admin_id' not in session:
        flash('Please login first!', 'warning')
        return redirect(url_for('admin_login'))
    
    """
    Admin route to delete a specific symptom log entry.
    """
    symptom_log_to_delete = SymptomLog.query.get_or_404(log_id)
    try:
        db.session.delete(symptom_log_to_delete)
        db.session.commit()
        flash(f'Symptom log entry for user {symptom_log_to_delete.user.email} on {symptom_log_to_delete.log_date} deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting symptom log entry: {e}', 'danger')
    return redirect(url_for('admin_manage_menstrual_health'))


# NEW: User Events Route
@app.route('/events')
def user_events():
    """
    User-facing route to display all events posted by admins.
    Events are ordered by event date, showing upcoming events first.
    """
    events = Event.query.order_by(Event.event_date.asc()).all()
    return render_template('user_events.html', events=events, UPLOAD_EVENT_FOLDER=app.config['UPLOAD_EVENT_FOLDER'])



# Error handler for 404 Not Found
@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create tables if they don't exist
        # Add a default admin if none exist (for initial setup)
        if Admin.query.count() == 0:
            print("No admin found. Creating a default admin...")
            default_admin = Admin(username='admin', email='admin@example.com')
            default_admin.set_password('adminpassword') # You should change this in production!
            db.session.add(default_admin)
            db.session.commit()
            print("Default admin 'admin@example.com' created with password 'adminpassword'")
        
        # Add a default user if none exist
        if User.query.count() == 0:
            print("No user found. Creating a default user...")
            default_user = User(
                full_name="Default User",
                email="user@example.com",
                phone_number="1234567890",
                date_of_birth=date(1990, 5, 15),
                marital_status="Single",
                state_of_origin="Lagos",
                lga="Ikeja",
                residential_address="123 Example St, Lagos",
                password=generate_password_hash('userpassword', method='pbkdf2:sha256')
            )
            db.session.add(default_user)
            db.session.commit()
            print("Default user 'user@example.com' created with password 'userpassword'")


    app.run(debug=True)
