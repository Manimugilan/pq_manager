from flask import Flask, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_babel import Babel
import os

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
babel = Babel()

def get_locale():
    return session.get('lang', request.accept_languages.best_match(['en', 'ta', 'hi', 'te', 'kn']) or 'en')

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object('config.Config')

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    babel.init_app(app, locale_selector=get_locale)

    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'warning'

    # Register blueprints
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # Create tables and instance folder (SQLite only)
    if 'sqlite' in app.config['SQLALCHEMY_DATABASE_URI']:
        try:
            os.makedirs(app.instance_path)
        except OSError:
            pass

        with app.app_context():
            db.create_all()

    return app
