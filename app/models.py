from app import db
from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import json, base64

ph = PasswordHasher()

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id                    = db.Column(db.Integer, primary_key=True)
    username              = db.Column(db.String(80), unique=True, nullable=False)
    password_hash         = db.Column(db.String(300), nullable=False)
    two_factor_enabled    = db.Column(db.Boolean, default=False)
    two_factor_secret     = db.Column(db.String(64))
    recovery_codes        = db.Column(db.Text)
    # Post-quantum keys (Kyber)
    pq_public_key         = db.Column(db.Text)          # base64 Kyber public key
    pq_private_key_enc    = db.Column(db.Text)          # base64 AES-encrypted Kyber private key
    pq_private_key_nonce  = db.Column(db.Text)          # nonce used to encrypt the private key
    # WebAuthn / Biometric
    webauthn_credential_id = db.Column(db.Text)
    webauthn_public_key    = db.Column(db.Text)
    webauthn_sign_count    = db.Column(db.Integer, default=0)
    master_key_salt       = db.Column(db.Text)          # base64 scrypt salt
    email                  = db.Column(db.String(120))
    reset_code            = db.Column(db.String(6))
    reset_expiry          = db.Column(db.DateTime)

    # ── Password helpers ──────────────────────────────────────────────────────
    def set_password(self, password):
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        try:
            return ph.verify(self.password_hash, password)
        except VerifyMismatchError:
            return False

    # ── Recovery code helpers ─────────────────────────────────────────────────
    def set_recovery_codes(self, codes: list):
        self.recovery_codes = json.dumps(codes)

    def get_recovery_codes(self) -> list:
        return json.loads(self.recovery_codes) if self.recovery_codes else []

    def use_recovery_code(self, code: str) -> bool:
        codes = self.get_recovery_codes()
        if code in codes:
            codes.remove(code)
            self.set_recovery_codes(codes)
            return True
        return False


class PasswordEntry(db.Model):
    __tablename__ = 'password_entry'
    id                 = db.Column(db.Integer, primary_key=True)
    user_id            = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    website            = db.Column(db.String(200), nullable=False)
    username           = db.Column(db.String(150))
    encrypted_password = db.Column(db.Text, nullable=False)   # AES-EAX encrypted
    kyber_ciphertext   = db.Column(db.Text, nullable=False)   # Kyber encapsulated shared key
    notes              = db.Column(db.Text)
    strength_score     = db.Column(db.Integer, default=0)
    shared_with        = db.Column(db.Text, default='[]')
    created_at         = db.Column(db.DateTime, server_default=db.func.now())
    updated_at         = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    user = db.relationship('User', backref=db.backref('passwords', lazy=True))

    def add_shared_user(self, user_id: int):
        shared = self.get_shared_users()
        if user_id not in shared:
            shared.append(user_id)
            self.shared_with = json.dumps(shared)

    def get_shared_users(self) -> list:
        return json.loads(self.shared_with) if self.shared_with else []
