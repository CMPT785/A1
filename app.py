from flask import Flask, session, g, request
from logging_config import setup_logging
from config import Config
from database import init_db
from auth import auth_bp, limiter
from security import add_security_headers

app = Flask(__name__)
app.config.from_object(Config)

setup_logging()
init_db()

# Initialize the Limiter with the Flask app
limiter.init_app(app)

@app.before_request
def before_request():
    g.user = None
    if 'username' in session:
        g.user = session['username']
        g.role = session['role']

@app.after_request
def after_request(response):
    response.headers['Server'] = ''
    return add_security_headers(response)

app.register_blueprint(auth_bp)

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'), port=5000)