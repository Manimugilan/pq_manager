import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'pq-dev-secret-change-in-production'
    # Use POSTGRES_URL (Vercel) or DATABASE_URL (generic) or SQLite fallback
    uri = os.environ.get('POSTGRES_URL') or os.environ.get('DATABASE_URL')
    if uri and uri.startswith("postgres://"):
        uri = uri.replace("postgres://", "postgresql://", 1)
    
    SQLALCHEMY_DATABASE_URI = uri or \
        'sqlite:///' + os.path.join(os.path.dirname(__file__), 'instance', 'vault.db')
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    
    # Secure Session Cookies for HTTPS (Vercel)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    BABEL_DEFAULT_LOCALE = 'en'
    BABEL_DEFAULT_TIMEZONE = 'UTC'
    BABEL_TRANSLATION_DIRECTORIES = 'translations'
    LANGUAGES = {
        'en': 'English',
        'ta': 'தமிழ்',
        'hi': 'हिन्दी',
        'te': 'తెలుగు',
        'kn': 'ಕನ್ನಡ'
    }
    # WebAuthn settings - RP_ID must be the domain (e.g. myapp.vercel.app)
    # On Vercel, we can use VERCEL_URL or a custom project domain
    BASE_DOMAIN = os.environ.get('VERCEL_URL', 'localhost')
    RP_ID = os.environ.get('RP_ID', BASE_DOMAIN)
    RP_NAME = 'PQ Password Manager'
    
    # ORIGIN must include the protocol (https:// for production)
    default_origin = f"https://{RP_ID}" if 'localhost' not in RP_ID else f"http://{RP_ID}:5002"
    ORIGIN = os.environ.get('ORIGIN', default_origin)
