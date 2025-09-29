from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import timedelta

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
socketio = SocketIO(async_mode='threading', cors_allowed_origins="*")
bcrypt = Bcrypt()
csrf = CSRFProtect()

def create_app(config_name=None):
    app = Flask(__name__)
    
    # Configuration
    if config_name:
        app.config.from_object(f'config.{config_name}')
    else:
        app.config.from_object('config.Config')
    
    # Sécurité des sessions
    app.config.update(
        SESSION_COOKIE_SECURE=False,  # Mettre True en production avec HTTPS
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(hours=24),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024  # 16MB max request size
    )
    
    # Initialisation des extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    socketio.init_app(app, cors_allowed_origins="*")
    bcrypt.init_app(app)
    csrf.init