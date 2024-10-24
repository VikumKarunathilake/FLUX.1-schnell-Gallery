# app.py
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import MySQLdb
from urllib.parse import urlparse
import mysql.connector
import os
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, ValidationError
from wtforms.validators import DataRequired, Length, EqualTo, Regexp
import re


# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

class User(UserMixin):
    def __init__(self, id, username, is_admin):
        self.id = id
        self.username = username
        self.is_admin = is_admin
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=20),
        Regexp(r'^[\w]+$', message="Username must contain only letters, numbers, and underscores")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long"),
        Regexp(r'.*[A-Z]', message="Password must contain at least one uppercase letter"),
        Regexp(r'.*[a-z]', message="Password must contain at least one lowercase letter"),
        Regexp(r'.*[0-9]', message="Password must contain at least one number"),
        Regexp(r'.*[!@#$%^&*()]', message="Password must contain at least one special character")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    registration_code = PasswordField('Registration Code', validators=[
        DataRequired(),
        Length(min=6, max=20)
    ])

    def validate_username(self, field):
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT id FROM users WHERE username = %s", (field.data,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')
        
@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    
    if user:
        return User(user['id'], user['username'], user['is_admin'])
    return None

def get_db():
    DATABASE_URL = os.getenv('DATABASE_URL')
    url = urlparse(DATABASE_URL)
    
    connection = mysql.connector.connect(
        host=url.hostname,
        user=url.username,
        password=url.password,
        database=url.path[1:],
        port=int(url.port) if url.port else 3306,
        ssl_ca=os.getenv('SSL_CA_PATH')  # Path to SSL certificate
    )
    return connection

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need administrator privileges to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=2)
    session.modified = True

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('gallery'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        try:
            conn = get_db()
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
            cur.close()
            conn.close()
            
            if user and check_password_hash(user['password'], password):
                user_obj = User(user['id'], user['username'], user['is_admin'])
                login_user(user_obj)
                flash('Logged in successfully.', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('gallery'))
            else:
                flash('Invalid username or password.', 'error')
                
        except Exception as e:
            flash('An error occurred during login.', 'error')
            app.logger.error(f'Login error: {str(e)}')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('gallery'))

@app.route('/')
def index():
    return render_template('index.html')
@app.route('/gallery')
def gallery():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 12
        offset = (page - 1) * per_page
        
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        
        # Get total count
        cur.execute("SELECT COUNT(*) as count FROM generated_images")
        total_images = cur.fetchone()['count']
        
        # Get paginated images
        cur.execute("""
            SELECT 
                id,
                generation_prompt,
                generation_timestamp,
                imgbb_display_url,
                generation_width,
                generation_height,
                generation_steps
            FROM generated_images 
            ORDER BY generation_timestamp DESC
            LIMIT %s OFFSET %s
        """, (per_page, offset))
        
        images = cur.fetchall()
        cur.close()
        conn.close()
        
        total_pages = (total_images + per_page - 1) // per_page
        
        return render_template('gallery.html',
                             images=images,
                             page=page,
                             total_pages=total_pages,
                             is_admin=current_user.is_authenticated and current_user.is_admin)
                             
    except Exception as e:
        app.logger.error(f'Gallery error: {str(e)}')
        flash('An error occurred while loading the gallery.', 'error')
        return render_template('gallery.html', images=[], page=1, total_pages=1)

@app.route('/image/<int:image_id>')
def image_detail(image_id):
    try:
        conn = get_db()
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT * FROM generated_images 
            WHERE id = %s
        """, (image_id,))
        image = cur.fetchone()
        cur.close()
        conn.close()
        
        if image:
            return render_template('image_detail.html',
                                 image=image,
                                 is_admin=current_user.is_authenticated and current_user.is_admin)
        
        flash('Image not found.', 'error')
        return redirect(url_for('gallery'))
        
    except Exception as e:
        app.logger.error(f'Image detail error: {str(e)}')
        flash('An error occurred while loading the image.', 'error')
        return redirect(url_for('gallery'))

@app.route('/image/<int:image_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_image(image_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM generated_images WHERE id = %s", (image_id,))
        if not cur.fetchone():
            flash('Image not found.', 'error')
            return redirect(url_for('gallery'))
        
        cur.execute("DELETE FROM generated_images WHERE id = %s", (image_id,))
        conn.commit()
        cur.close()
        conn.close()
        
        flash('Image successfully deleted.', 'success')
        return redirect(url_for('gallery'))
        
    except Exception as e:
        app.logger.error(f'Delete image error: {str(e)}')
        flash('An error occurred while deleting the image.', 'error')
        return redirect(url_for('gallery'))

def validate_username(self, field):
    conn = get_db()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id FROM users WHERE username = %s", (field.data,))
    user = cur.fetchone()
    cur.close()
    conn.close()
        
    if user:
        raise ValidationError('Username already exists. Please choose a different one.')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('gallery'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        if form.registration_code.data != os.getenv('REGISTRATION_CODE'):
            flash('Invalid registration code.', 'error')
            return render_template('register.html', form=form)
            
        try:
            conn = get_db()
            cur = conn.cursor()
            
            # Hash the password before storing
            hashed_password = generate_password_hash(form.password.data)
            
            # Insert new user
            cur.execute("""
                INSERT INTO users (username, password, is_admin, created_at)
                VALUES (%s, %s, %s, NOW())
            """, (form.username.data, hashed_password, True))
            
            conn.commit()
            cur.close()
            conn.close()
            
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login')) 
            
        except Exception as e:
            app.logger.error(f'Registration error: {str(e)}')
            flash('An error occurred during registration.', 'error')
            return render_template('register.html', form=form)
    
    return render_template('register.html', form=form)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server error: {str(error)}')
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=False)