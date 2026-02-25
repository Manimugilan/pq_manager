from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, session, current_app, jsonify)
from flask_login import login_user, logout_user, current_user, login_required
from flask_babel import gettext as _
from app import db, login_manager
from app.models import User
from app.encryption import (
    verify_totp_code, generate_totp_secret, get_totp_uri,
    generate_recovery_codes, generate_pq_keypair,
    encrypt_private_key, derive_master_key
)
import pyotp
import qrcode
import io
import base64
import json

# WebAuthn
try:
    import webauthn
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria, UserVerificationRequirement,
        AuthenticatorAttachment, ResidentKeyRequirement
    )
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False

auth = Blueprint('auth', __name__)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ── Language Switcher ─────────────────────────────────────────────────────────
@auth.route('/set_language/<lang>')
def set_language(lang):
    allowed = current_app.config.get('LANGUAGES', {})
    if lang in allowed:
        session['lang'] = lang
    return redirect(request.referrer or url_for('main.index'))


# ── Register ──────────────────────────────────────────────────────────────────
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        if not username or not password:
            flash(_('All fields are required.'), 'danger')
            return render_template('register.html')

        if password != confirm:
            flash(_('Passwords do not match.'), 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash(_('Username already taken.'), 'danger')
            return render_template('register.html')

        # Derive master key from password (used to protect the PQ private key)
        master_key, salt_b64 = derive_master_key(password)

        # Generate Kyber key pair
        try:
            pub_key_b64, priv_key_b64 = generate_pq_keypair()
            enc_priv_b64, nonce_b64   = encrypt_private_key(priv_key_b64, master_key)
        except RuntimeError as e:
            # liboqs not installed — skip PQ key generation gracefully
            pub_key_b64 = enc_priv_b64 = nonce_b64 = None

        user = User(
            username=username,
            email=email,
            pq_public_key=pub_key_b64,
            pq_private_key_enc=enc_priv_b64,
            pq_private_key_nonce=nonce_b64,
            master_key_salt=salt_b64,
        )
        user.set_password(password)
        # Store the scrypt salt in the 2FA secret field temporarily — or add a dedicated column
        # For now store it alongside other fields (add master_key_salt column ideally)
        db.session.add(user)
        db.session.commit()

        flash(_('Account created! Please log in.'), 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


# ── Login ─────────────────────────────────────────────────────────────────────
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # ── 1. Derive/Retrieve Master Key ───────────────────────────────
            try:
                if user.master_key_salt:
                    salt_bytes = base64.b64decode(user.master_key_salt)
                    m_key, tmp_salt = derive_master_key(password, salt_bytes)
                else:
                    # New salt for legacy user
                    m_key, salt_b64 = derive_master_key(password)
                    user.master_key_salt = salt_b64
                    db.session.commit()
                
                session['master_key'] = base64.b64encode(m_key).decode()
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Login crypto error: {str(e)}")
                flash(_('Security error during login.'), 'danger')
                return redirect(url_for('auth.login'))

            # ── 2. Legacy Keypair Upgrade ───────────────────────────────────
            if not user.pq_public_key:
                try:
                    from app.encryption import generate_pq_keypair, encrypt_private_key
                    pub_b64, priv_b64 = generate_pq_keypair()
                    enc_priv_b64, nonce_b64 = encrypt_private_key(priv_b64, m_key)
                    user.pq_public_key = pub_b64
                    user.pq_private_key_enc = enc_priv_b64
                    user.pq_private_key_nonce = nonce_b64
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    current_app.logger.error(f"Legacy upgrade failed: {str(e)}")

            if user.two_factor_enabled:
                session['pending_user_id'] = user.id
                return redirect(url_for('auth.verify_2fa'))

            login_user(user, remember=True)
            flash(_('Welcome back, %(name)s!', name=user.username), 'success')
            return redirect(url_for('main.index'))


        flash(_('Invalid username or password.'), 'danger')

    return render_template('login.html')


# ── Logout ────────────────────────────────────────────────────────────────────
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


# ── 2FA Setup ─────────────────────────────────────────────────────────────────
@auth.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if not current_user.two_factor_secret:
        current_user.two_factor_secret = generate_totp_secret()
        db.session.commit()

    if request.method == 'POST':
        code = request.form.get('code', '')
        if verify_totp_code(current_user.two_factor_secret, code):
            codes = generate_recovery_codes()
            current_user.set_recovery_codes(codes)
            current_user.two_factor_enabled = True
            db.session.commit()
            flash(_('2FA enabled! Save your recovery codes.'), 'success')
            return render_template('setup_2fa.html',
                                   setup_complete=True,
                                   recovery_codes=codes)
        flash(_('Invalid verification code. Try again.'), 'danger')

    totp_uri = get_totp_uri(current_user.two_factor_secret, current_user.username)

    # Generate QR code as base64 image
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='white', back_color='black')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template('setup_2fa.html',
                           qr_b64=qr_b64,
                           secret=current_user.two_factor_secret)


# ── 2FA Verify ────────────────────────────────────────────────────────────────
@auth.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_user_id' not in session:
        return redirect(url_for('auth.login'))

    user = User.query.get(session['pending_user_id'])
    if not user:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code          = request.form.get('code', '')
        recovery_code = request.form.get('recovery_code', '').strip().upper()

        if code and verify_totp_code(user.two_factor_secret, code):
            login_user(user, remember=True)
            session.pop('pending_user_id', None)
            return redirect(url_for('main.index'))

        if recovery_code and user.use_recovery_code(recovery_code):
            db.session.commit()
            login_user(user, remember=True)
            session.pop('pending_user_id', None)
            flash(_('Logged in with recovery code. Please set up 2FA again.'), 'warning')
            return redirect(url_for('main.index'))

        flash(_('Invalid verification code.'), 'danger')

    return render_template('verify_2fa.html')


# ── Biometric Registration ─────────────────────────────────────────────────────
@auth.route('/biometric/register/begin', methods=['POST'])
@login_required
def biometric_register_begin():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available'}), 500

    options = webauthn.generate_registration_options(
        rp_id=current_app.config['RP_ID'],
        rp_name=current_app.config['RP_NAME'],
        user_id=str(current_user.id).encode(),
        user_name=current_user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
            require_resident_key=False
        )
    )
    session['webauthn_reg_challenge'] = base64.b64encode(options.challenge).decode()
    return jsonify(webauthn.options_to_json(options))


@auth.route('/biometric/register/complete', methods=['POST'])
@login_required
def biometric_register_complete():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available'}), 500

    try:
        credential = webauthn.verify_registration_response(
            credential=request.get_json(),
            expected_challenge=base64.b64decode(session['webauthn_reg_challenge']),
            expected_rp_id=current_app.config['RP_ID'],
            expected_origin=current_app.config['ORIGIN']
        )
        current_user.webauthn_credential_id = base64.b64encode(credential.credential_id).decode()
        current_user.webauthn_public_key     = base64.b64encode(credential.credential_public_key).decode()
        current_user.webauthn_sign_count     = credential.sign_count
        db.session.commit()
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ── Biometric Login ────────────────────────────────────────────────────────────
@auth.route('/biometric/login/begin', methods=['POST'])
def biometric_login_begin():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available'}), 500

    data     = request.get_json()
    username = data.get('username', '')
    user     = User.query.filter_by(username=username).first()

    if not user or not user.webauthn_credential_id:
        return jsonify({'error': 'No biometric registered'}), 404

    options = webauthn.generate_authentication_options(
        rp_id=current_app.config['RP_ID'],
        allow_credentials=[
            webauthn.helpers.structs.PublicKeyCredentialDescriptor(
                id=base64.b64decode(user.webauthn_credential_id)
            )
        ],
        user_verification=UserVerificationRequirement.PREFERRED
    )
    session['webauthn_auth_challenge'] = base64.b64encode(options.challenge).decode()
    session['webauthn_user_id']        = user.id
    return jsonify(webauthn.options_to_json(options))


@auth.route('/biometric/login/complete', methods=['POST'])
def biometric_login_complete():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn not available'}), 500

    user = User.query.get(session.get('webauthn_user_id'))
    if not user:
        return jsonify({'error': 'Session expired'}), 400

    try:
        auth_ver = webauthn.verify_authentication_response(
            credential=request.get_json(),
            expected_challenge=base64.b64decode(session['webauthn_auth_challenge']),
            expected_rp_id=current_app.config['RP_ID'],
            expected_origin=current_app.config['ORIGIN'],
            credential_public_key=base64.b64decode(user.webauthn_public_key),
            credential_current_sign_count=user.webauthn_sign_count
        )
        user.webauthn_sign_count = auth_ver.new_sign_count
        db.session.commit()
        login_user(user, remember=True)
        return jsonify({'status': 'ok', 'redirect': url_for('main.index')})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# ── Forgot Password ───────────────────────────────────────────────────────────
@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user  = User.query.filter_by(email=email).first()
        
        if user:
            import random, datetime
            code = str(random.randint(100000, 999999))
            user.reset_code = code
            user.reset_expiry = datetime.datetime.now() + datetime.timedelta(minutes=15)
            db.session.commit()
            
            # TODO: Integrate Flask-Mail. For now, we "mock" send it to logs.
            current_app.logger.info(f"RESET CODE for {user.username} ({email}): {code}")
            
            session['reset_email'] = email
            flash(_('A 6-digit verification code has been sent to your email.'), 'info')
            return redirect(url_for('auth.reset_password'))
        
        # Security: don't reveal if email belongs to a user
        flash(_('If that email is registered, a code has been sent.'), 'info')
        return redirect(url_for('auth.forgot_password'))
        
    return render_template('forgot_password.html')


@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('reset_email')
    if not email:
        return redirect(url_for('auth.forgot_password'))
        
    if request.method == 'POST':
        code     = request.form.get('code', '').strip()
        new_pwd  = request.form.get('password', '')
        confirm  = request.form.get('confirm', '')
        
        user = User.query.filter_by(email=email).first()
        import datetime
        if not user or user.reset_code != code or datetime.datetime.now() > user.reset_expiry:
            flash(_('Invalid or expired verification code.'), 'danger')
            return render_template('reset_password.html')
            
        if new_pwd != confirm:
            flash(_('Passwords do not match.'), 'danger')
            return render_template('reset_password.html')
            
        # ⚠️ DATA LOSS WARNING ⚠️
        # Password reset breaks existing vault encryption.
        user.set_password(new_pwd)
        
        # Clear reset code
        user.reset_code = None
        user.reset_expiry = None
        
        # Force re-generation of keys on next login (legacy path)
        user.pq_public_key = None
        user.pq_private_key_enc = None
        user.pq_private_key_nonce = None
        user.master_key_salt = None
        
        db.session.commit()
        session.pop('reset_email', None)
        
        flash(_('Password reset successful! Your vault has been reset. Please log in.'), 'success')
        return redirect(url_for('auth.login'))
        
    return render_template('reset_password.html')
