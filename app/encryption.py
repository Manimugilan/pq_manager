"""
encryption.py — Complete Kyber (ML-KEM) + AES-EAX encryption module
Uses liboqs-python for post-quantum key encapsulation mechanism (KEM).
Falls back to AES-256 based KEM simulation when liboqs is unavailable.
"""
import base64
import secrets
import pyotp
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ── Kyber (Post-Quantum KEM) ────────────────────────────────────────────────
import os
OQS_AVAILABLE = False
if os.environ.get('VERCEL') != '1':
    try:
        import oqs
        # Quick sanity check — instantiate to verify native lib is working
        _test_kem = oqs.KeyEncapsulation('Kyber512')
        _test_kem.generate_keypair()
        _test_kem.free()
        OQS_AVAILABLE = True
        print("[PQ Vault] ✅ liboqs Kyber512 available — post-quantum encryption active.")
    except Exception:
        OQS_AVAILABLE = False
        print("[PQ Vault] ⚠️  liboqs not available — falling back to AES-256 KEM simulation.")
else:
    print("[PQ Vault] ☁️  Vercel environment detected — using AES-256 KEM simulation.")

KEM_ALGORITHM = 'Kyber512'


# ── Fallback: AES-256 KEM simulation ────────────────────────────────────────
# When liboqs is unavailable we simulate the KEM API using asymmetric-style
# AES key wrapping: a fresh 32-byte secret is generated, encrypted with the
# "public key" (which is itself an AES key stored as the public key), and
# returned as both the ciphertext and shared secret.  This keeps the rest of
# the codebase unchanged while still providing strong AES-256 encryption.

class _FallbackKEM:
    """
    Minimal KEM fallback using AES-256-EAX key wrapping.
    Public key  = a 32-byte random symmetric key (stored b64).
    Encapsulate = generate a fresh 32-byte session key, AES-wrap it under the
                  public key and return (wrapped_key_blob, session_key).
    Decapsulate = AES-unwrap the blob using the stored private key (= public key).
    """

    MARKER = b'FKEM'   # 4-byte magic so we can detect fallback blobs

    @staticmethod
    def generate_keypair():
        """Returns (public_key_bytes, private_key_bytes) — identical 32-byte key."""
        key = get_random_bytes(32)
        return key, key   # symmetric: pub == priv in this fallback

    @staticmethod
    def encapsulate(public_key_bytes: bytes):
        """
        Returns (ciphertext_bytes, shared_secret_bytes).
        ciphertext = MARKER + nonce(16) + tag(16) + encrypted_session_key
        """
        session_key = get_random_bytes(32)
        cipher = AES.new(public_key_bytes[:32], AES.MODE_EAX)
        ct, tag = cipher.encrypt_and_digest(session_key)
        blob = _FallbackKEM.MARKER + cipher.nonce + tag + ct
        return blob, session_key

    @staticmethod
    def decapsulate(ciphertext_bytes: bytes, private_key_bytes: bytes) -> bytes:
        """Recovers the 32-byte session key from the ciphertext blob."""
        if ciphertext_bytes[:4] != _FallbackKEM.MARKER:
            raise ValueError("Not a fallback KEM blob")
        nonce = ciphertext_bytes[4:20]
        tag   = ciphertext_bytes[20:36]
        ct    = ciphertext_bytes[36:]
        cipher = AES.new(private_key_bytes[:32], AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ct, tag)


# ── Public KEM API ────────────────────────────────────────────────────────────

def generate_pq_keypair():
    """
    Generate a Kyber (or fallback) public/private key pair.
    Returns (public_key_b64: str, private_key_b64: str)
    """
    if OQS_AVAILABLE:
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            public_key  = kem.generate_keypair()
            private_key = kem.export_secret_key()
    else:
        public_key, private_key = _FallbackKEM.generate_keypair()

    return (
        base64.b64encode(public_key).decode('utf-8'),
        base64.b64encode(private_key).decode('utf-8')
    )


def encapsulate_shared_key(public_key_b64: str):
    """
    Encapsulate a shared secret using the recipient's public key.
    Returns (ciphertext_b64: str, shared_secret: bytes)
    """
    public_key = base64.b64decode(public_key_b64)

    if OQS_AVAILABLE:
        with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
    else:
        ciphertext, shared_secret = _FallbackKEM.encapsulate(public_key)

    return (
        base64.b64encode(ciphertext).decode('utf-8'),
        shared_secret   # raw bytes — use first 32 for AES-256
    )


def decapsulate_shared_key(ciphertext_b64: str, private_key_b64: str) -> bytes:
    """
    Decapsulate the shared secret using the stored private key.
    Returns shared_secret: bytes
    """
    ciphertext  = base64.b64decode(ciphertext_b64)
    private_key = base64.b64decode(private_key_b64)

    if OQS_AVAILABLE:
        with oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=private_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
    else:
        shared_secret = _FallbackKEM.decapsulate(ciphertext, private_key)

    return shared_secret


# ── AES-EAX Authenticated Encryption ────────────────────────────────────────
def aes_encrypt(data: str, key: bytes) -> str:
    """Encrypt plaintext using AES-256-EAX. Returns base64-encoded blob."""
    cipher = AES.new(key[:32], AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    blob = cipher.nonce + tag + ciphertext   # nonce(16) + tag(16) + ciphertext
    return base64.b64encode(blob).decode('utf-8')


def aes_decrypt(encrypted_b64: str, key: bytes) -> str:
    """Decrypt AES-256-EAX blob. Returns original plaintext string."""
    blob       = base64.b64decode(encrypted_b64)
    nonce      = blob[:16]
    tag        = blob[16:32]
    ciphertext = blob[32:]
    cipher = AES.new(key[:32], AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')


# ── Private Key Envelope ─────────────────────────────────────────────────────
def encrypt_private_key(private_key_b64: str, master_key: bytes):
    """
    AES-encrypt the KEM private key using the per-user master key.
    Returns (encrypted_b64, nonce_b64)
    """
    nonce = get_random_bytes(16)
    cipher = AES.new(master_key[:32], AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(private_key_b64.encode('utf-8'))
    blob = tag + ciphertext
    return (
        base64.b64encode(blob).decode('utf-8'),
        base64.b64encode(nonce).decode('utf-8')
    )


def decrypt_private_key(encrypted_b64: str, nonce_b64: str, master_key: bytes) -> str:
    """Decrypt the stored KEM private key. Returns private_key_b64 string."""
    blob  = base64.b64decode(encrypted_b64)
    nonce = base64.b64decode(nonce_b64)
    tag        = blob[:16]
    ciphertext = blob[16:]
    cipher = AES.new(master_key[:32], AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')


def derive_master_key(password: str, salt: bytes = None):
    """
    Derive a 32-byte master key from the user's password using scrypt.
    Returns (key: bytes, salt_b64: str)
    """
    from Crypto.Protocol.KDF import scrypt
    if salt is None:
        salt = get_random_bytes(32)
    key = scrypt(
        password=password.encode('utf-8'),
        salt=salt,
        key_len=32,
        N=2**14,
        r=8,
        p=1
    )
    return key, base64.b64encode(salt).decode('utf-8')


# ── TOTP / 2FA ───────────────────────────────────────────────────────────────
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def verify_totp_code(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def get_totp_uri(secret: str, username: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name='PQ Password Manager'
    )


# ── Recovery Codes ───────────────────────────────────────────────────────────
def generate_recovery_codes(count: int = 8) -> list:
    """Generate secure recovery codes (8 codes, 8 hex chars each)."""
    return [secrets.token_hex(4).upper() for _ in range(count)]
