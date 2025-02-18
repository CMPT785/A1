import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)
        ''', ('admin', generate_password_hash('admin'), 'admin'))
        conn.commit()
