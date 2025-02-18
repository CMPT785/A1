import re
import logging
from flask import jsonify

def validate_input(data):
    if not data or not isinstance(data, dict):
        logging.debug('Invalid input: data is not a dictionary or is empty')
        return False, 'Invalid input: data is not a dictionary or is empty'
    for key, value in data.items():
        if not isinstance(value, str) or not re.match(r'^[a-zA-Z0-9_]+$', value):
            logging.debug(f'Invalid input: {key}={value} does not match required pattern')
            return False, f'Invalid input: {key} does not match required pattern'
    return True, ''

def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response