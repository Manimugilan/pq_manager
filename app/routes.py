from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, jsonify, Response, current_app)
from flask_login import login_required, current_user
from flask_babel import gettext as _
from app import db
from app.models import User, PasswordEntry
from app.encryption import (
    aes_encrypt, aes_decrypt,
    encapsulate_shared_key, decapsulate_shared_key,
    decrypt_private_key, derive_master_key
)
from app.password_utils import generate_password, analyze_password_strength
import json, base64
from io import StringIO

main = Blueprint('main', __name__)


# ── Dashboard ─────────────────────────────────────────────────────────────────
@main.route('/')
@login_required
def index():
    entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()
    shared  = PasswordEntry.query.filter(
        PasswordEntry.shared_with.contains(str(current_user.id))
    ).all()
    return render_template('dashboard.html', entries=entries, shared=shared)


# ── Add Password ──────────────────────────────────────────────────────────────
@main.route('/add', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        website  = request.form.get('website', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        notes    = request.form.get('notes', '')

        if not website or not password:
            flash(_('Website and password are required.'), 'danger')
            return render_template('add_password.html')

        # Kyber encapsulate using this user's public key
        # Generate keys on the fly if user has none (legacy account)
        if not current_user.pq_public_key:
            from app.encryption import generate_pq_keypair, encrypt_private_key
            from flask import session as flask_session
            pub_b64, priv_b64 = generate_pq_keypair()
            master_key_b64 = flask_session.get('master_key')
            if master_key_b64:
                master_key = base64.b64decode(master_key_b64)
                enc_priv, nonce_b64 = encrypt_private_key(priv_b64, master_key)
                current_user.pq_public_key        = pub_b64
                current_user.pq_private_key_enc   = enc_priv
                current_user.pq_private_key_nonce = nonce_b64
                db.session.commit()
            else:
                current_user.pq_public_key = pub_b64
        ciphertext_b64, shared_secret = encapsulate_shared_key(current_user.pq_public_key)
        encrypted_password = aes_encrypt(password, shared_secret[:32])
        strength = analyze_password_strength(password)

        entry = PasswordEntry(
            user_id=current_user.id,
            website=website,
            username=username,
            encrypted_password=encrypted_password,
            kyber_ciphertext=ciphertext_b64,
            notes=notes,
            strength_score=strength['score']
        )
        db.session.add(entry)
        db.session.commit()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'ok', 'id': entry.id})

        flash(_('Password added successfully!'), 'success')
        return redirect(url_for('main.index'))

    return render_template('add_password.html')


# ── View / Decrypt Password ───────────────────────────────────────────────────
@main.route('/view/<int:entry_id>')
@login_required
def view_password(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)

    if entry.user_id != current_user.id and current_user.id not in entry.get_shared_users():
        flash(_('Unauthorized access.'), 'danger')
        return redirect(url_for('main.index'))

    # Re-derive master key requires password — for now use a session token
    # Decapsulate using stored Kyber private key
    # NOTE: pq_private_key_enc requires master_key which is derived at login
    # We store decryption key in session for the session lifetime
    master_key_b64 = session_get_master_key()
    if not master_key_b64:
        from flask_login import logout_user
        logout_user()
        flash(_('Session expired. Please log in again.'), 'warning')
        return redirect(url_for('auth.login'))

    master_key = base64.b64decode(master_key_b64)
    priv_key_b64 = decrypt_private_key(
        current_user.pq_private_key_enc,
        current_user.pq_private_key_nonce,
        master_key
    )
    shared_secret = decapsulate_shared_key(entry.kyber_ciphertext, priv_key_b64)
    decrypted = aes_decrypt(entry.encrypted_password, shared_secret[:32])

    return render_template('view_password.html', entry=entry, password=decrypted)


# ── Edit Password ─────────────────────────────────────────────────────────────
@main.route('/edit/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def edit_password(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash(_('Unauthorized.'), 'danger')
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        entry.website  = request.form.get('website', entry.website)
        entry.username = request.form.get('username', entry.username)
        entry.notes    = request.form.get('notes', entry.notes)

        if password:
            ciphertext_b64, shared_secret = encapsulate_shared_key(current_user.pq_public_key)
            entry.encrypted_password = aes_encrypt(password, shared_secret[:32])
            entry.kyber_ciphertext   = ciphertext_b64
            s = analyze_password_strength(password)
            entry.strength_score = s['score']

        db.session.commit()
        flash(_('Entry updated.'), 'success')
        return redirect(url_for('main.index'))

    return render_template('edit_password.html', entry=entry)


# ── Delete Password ───────────────────────────────────────────────────────────
@main.route('/delete/<int:entry_id>', methods=['POST'])
@login_required
def delete_password(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    db.session.delete(entry)
    db.session.commit()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status': 'ok'})
    flash(_('Entry deleted.'), 'info')
    return redirect(url_for('main.index'))


# ── Share Password ────────────────────────────────────────────────────────────
@main.route('/share/<int:entry_id>', methods=['GET', 'POST'])
@login_required
def share_password(entry_id):
    entry = PasswordEntry.query.get_or_404(entry_id)
    if entry.user_id != current_user.id:
        flash(_('Unauthorized.'), 'danger')
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        user = User.query.filter_by(username=username).first()
        if user and user.id != current_user.id:
            entry.add_shared_user(user.id)
            db.session.commit()
            flash(_('Password shared with %(u)s.', u=username), 'success')
        else:
            flash(_('User not found.'), 'danger')

    shared_users = User.query.filter(User.id.in_(entry.get_shared_users())).all()
    return render_template('share_password.html', entry=entry, shared_users=shared_users)


# ── Password Strength API ─────────────────────────────────────────────────────
@main.route('/api/strength', methods=['POST'])
def password_strength():
    data     = request.get_json()
    password = data.get('password', '')
    result   = analyze_password_strength(password)
    return jsonify(result)


# ── Generate Password API ─────────────────────────────────────────────────────
@main.route('/api/generate')
@login_required
def generate_password_api():
    length  = int(request.args.get('length', 16))
    symbols = request.args.get('symbols', 'true') == 'true'
    pwd     = generate_password(length, symbols)
    return jsonify({'password': pwd, 'strength': analyze_password_strength(pwd)})


# ── Backup (JSON, NOT plaintext CSV) ─────────────────────────────────────────
@main.route('/backup')
@login_required
def backup():
    return render_template('backup_restore.html')


@main.route('/backup/export')
@login_required
def backup_export():
    master_key_b64 = session_get_master_key()
    if not master_key_b64:
        from flask_login import logout_user
        logout_user()
        flash(_('Session expired (master key missing). Please log in again.'), 'warning')
        return redirect(url_for('auth.login'))

    try:
        master_key   = base64.b64decode(master_key_b64)
        if not current_user.pq_private_key_enc or not current_user.pq_private_key_nonce:
            flash(_('Account encryption keys are missing. Please re-save your profile or contact support.'), 'danger')
            return redirect(url_for('main.index'))

        priv_key_b64 = decrypt_private_key(
            current_user.pq_private_key_enc,
            current_user.pq_private_key_nonce,
            master_key
        )
        
        entries = PasswordEntry.query.filter_by(user_id=current_user.id).all()
        data = []
        errors = 0
        
        for e in entries:
            try:
                shared_secret = decapsulate_shared_key(e.kyber_ciphertext, priv_key_b64)
                pwd = aes_decrypt(e.encrypted_password, shared_secret[:32])
                data.append({
                    'website': e.website,
                    'username': e.username,
                    'password': pwd,
                    'notes': e.notes,
                    'strength': e.strength_score,
                    'created_at': str(e.created_at)
                })
            except Exception as decrypt_err:
                current_app.logger.error(f"Failed to decrypt entry {e.id}: {str(decrypt_err)}")
                errors += 1
                # Still add the entry with an error message or skip it
                data.append({
                    'website': e.website,
                    'username': e.username,
                    'password': '[DECRYPTION_FAILED]',
                    'notes': f"Error: {str(decrypt_err)}. {e.notes}",
                    'error': True
                })

        if errors > 0:
            flash(_('%(n)s entries failed to decrypt and were marked in the backup.', n=errors), 'warning')

        payload = json.dumps(data, ensure_ascii=False, indent=2)
        return Response(
            payload,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=vault_backup.json'}
        )
    except Exception as e:
        current_app.logger.error(f"Backup export failed: {str(e)}")
        flash(_('Backup failed: %(err)s', err=str(e)), 'danger')
        return redirect(url_for('main.backup'))


@main.route('/backup/import', methods=['POST'])
@login_required
def backup_import():
    f = request.files.get('backup_file')
    if not f or not f.filename.endswith('.json'):
        flash(_('Please upload a valid .json backup file.'), 'danger')
        return redirect(url_for('main.backup'))

    if not current_user.pq_public_key:
        flash(_('Encryption keys missing. Please go to Settings to re-generate keys before importing.'), 'danger')
        return redirect(url_for('main.backup'))

    try:
        raw_data = f.read().decode('utf-8')
        data = json.loads(raw_data)
        if not isinstance(data, list):
            raise ValueError("Backup data must be a list of entries.")
            
        count = 0
        for row in data:
            if not row.get('password'):
                continue
            ct_b64, shared_secret = encapsulate_shared_key(current_user.pq_public_key)
            enc_pwd = aes_encrypt(row.get('password', ''), shared_secret[:32])
            entry = PasswordEntry(
                user_id=current_user.id,
                website=row.get('website', 'Imported Site'),
                username=row.get('username', ''),
                encrypted_password=enc_pwd,
                kyber_ciphertext=ct_b64,
                notes=row.get('notes', ''),
                strength_score=row.get('strength', 0)
            )
            db.session.add(entry)
            count += 1
            
        db.session.commit()
        flash(_('Backup imported successfully! %(n)s entries added.', n=count), 'success')
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Import failed: {str(e)}")
        flash(_('Import failed: %(err)s', err=str(e)), 'danger')

    return redirect(url_for('main.index'))


# ── Helper: retrieve master key from session ──────────────────────────────────
def session_get_master_key():
    """Return the base64 master key stored in the session, or None."""
    from flask import session
    return session.get('master_key')
