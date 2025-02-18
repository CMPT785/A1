from flask import Blueprint, request, jsonify, session, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import logging
from security import validate_input

auth_bp = Blueprint('auth', __name__)

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