import os
import hmac
import hashlib
import base64
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import bcrypt
import pyotp


def get_aes_key(secret_key_env: str | None, fallback_secret_bytes: bytes) -> bytes:
    if secret_key_env:
        # accept 32 or 44 chars base64 or hex; otherwise treat as raw
        try:
            if all(c in "0123456789abcdef" for c in secret_key_env.lower()) and len(secret_key_env) in (32, 64):
                return bytes.fromhex(secret_key_env)
            decoded = base64.b64decode(secret_key_env)
            if len(decoded) in (16, 24, 32):
                return decoded
        except Exception:
            pass
    # derive 32 bytes from fallback secret using SHA256
    return hashlib.sha256(fallback_secret_bytes).digest()


def aes_encrypt(plaintext: str, key: bytes) -> Tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return ciphertext, nonce


def aes_decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")


def bcrypt_hash(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def bcrypt_verify(password: str, hashed: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed)
    except ValueError:
        return False


def integrity_hash_str(*parts: str) -> str:
    data = "|".join(parts).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_now(secret: str) -> str:
    return pyotp.TOTP(secret).now()


def verify_totp(secret: str, token: str) -> bool:
    try:
        return pyotp.TOTP(secret).verify(token, valid_window=1)
    except Exception:
        return False
