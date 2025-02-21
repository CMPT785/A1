from flask import Blueprint, request, jsonify, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import logging
import re
from security import validate_input
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

auth_bp = Blueprint('auth', __name__)

# Custom handler for rate limit breaches
def rate_limit_exceeded(e):
    return jsonify({'error': 'Max attempts exceeded. Please try again later.', 'status': 429}), 429

# Initialize the Limiter
limiter = Limiter(
    get_remote_address,
    default_limits=["40 per day", "5 per hour"],
    on_breach=rate_limit_exceeded
)

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    return True, ""

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    is_valid, error_message = validate_input(data)
    if not is_valid:
        return jsonify({'error': error_message, 'status': 400}), 400
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password are required', 'status': 400}), 400
    
    is_valid_password, password_error_message = validate_password(password)
    if not is_valid_password:
        return jsonify({'error': password_error_message, 'status': 400}), 400
    
    hashed_password = generate_password_hash(password)
    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, 'user'))
            conn.commit()
        logging.info(f'User {username} registered')
        return jsonify({'message': 'User registered successfully', 'status': 201}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists', 'status': 400}), 400

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")  # Add rate limiting to the login route
def login():
    data = request.get_json()
    is_valid, error_message = validate_input(data)
    if not is_valid:
        return jsonify({'error': error_message, 'status': 400}), 400
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password are required', 'status': 400}), 400
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user[2], password):
            session['username'] = username
            session['role'] = user[3]
            session.permanent = True
            logging.info(f'User {username} logged in')
            return jsonify({'message': 'Login successful', 'status': 200}), 200
        logging.warning(f'Failed login attempt for username: {username}')
        return jsonify({'error': 'Invalid credentials', 'status': 401}), 401

@auth_bp.route('/changepw', methods=['POST'])
@limiter.limit("10 per day")  # Add rate limiting to the change password route
def change_password():
    data = request.get_json()
    logging.debug(f'Received change password request: {data.get("username")}')
    is_valid, error_message = validate_input(data)
    if not is_valid:
        return jsonify({'error': error_message, 'status': 400}), 400
    username = data.get('username')
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    if not username or not old_password or not new_password:
        return jsonify({'error': 'All fields are required', 'status': 400}), 400
    
    is_valid_password, password_error_message = validate_password(new_password)
    if not is_valid_password:
        return jsonify({'error': password_error_message, 'status': 400}), 400
    
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user[2], old_password):
            hashed_password = generate_password_hash(new_password)
            cursor.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
            conn.commit()
            logging.info(f'User {username} changed their password')
            return jsonify({'message': 'Password changed successfully', 'status': 201}), 201
        return jsonify({'error': 'Invalid credentials', 'status': 400}), 400

@auth_bp.route('/admin', methods=['GET'])
def admin():
    if g.user and g.role == 'admin':
        return jsonify({'message': f'Logged in as admin {g.user}', 'status': 200}), 200
    return jsonify({'error': 'Unauthorized access', 'status': 401}), 401

@auth_bp.route('/user', methods=['GET'])
def user():
    if g.user:
        return jsonify({'message': f'Logged in as user {g.user}', 'status': 200}), 200
    return jsonify({'error': 'Unauthorized access', 'status': 401}), 401

@auth_bp.route('/health', methods=['GET'])
def health():
    return jsonify({'message': 'Healthy', 'status': 200}), 200