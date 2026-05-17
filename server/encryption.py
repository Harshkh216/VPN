"""
encryption.py - AES Encryption / Decryption Utilities
Provides symmetric AES-256-GCM encryption for all VPN tunnel messages.

Why AES-GCM?
  - AES-256: 256-bit key, unbroken by any known attack.
  - GCM mode: Authenticated encryption — detects tampering (integrity + confidentiality).
  - Each message gets a unique random nonce so identical plaintexts encrypt differently.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ──────────────────────────────────────────────
# Key Generation
# ──────────────────────────────────────────────

def generate_aes_key() -> bytes:
    """
    Generate a cryptographically random 256-bit (32-byte) AES key.
    This key is exchanged during the SSL handshake and used for the session.
    """
    return os.urandom(32)


def derive_key_from_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """
    Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256.
    
    PBKDF2 with 480,000 iterations slows down brute-force attacks significantly.
    Returns (key, salt) so the salt can be stored for later re-derivation.
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    key = kdf.derive(password.encode())
    return key, salt


# ──────────────────────────────────────────────
# AES-GCM Encrypt / Decrypt
# ──────────────────────────────────────────────

def encrypt_message(key: bytes, plaintext: str) -> str:
    """
    Encrypt a UTF-8 string with AES-256-GCM.

    Wire format (base64-encoded):  nonce(12) || ciphertext+tag
    The 12-byte nonce is prepended so the receiver can split it off.

    Returns a base64 string safe for transmission over the socket.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)                         # GCM standard nonce size
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    # Concatenate nonce + ciphertext and encode to base64 for safe transport
    return base64.b64encode(nonce + ciphertext).decode('utf-8')


def decrypt_message(key: bytes, token: str) -> str:
    """
    Decrypt a base64-encoded AES-256-GCM token back to a UTF-8 string.

    Raises cryptography.exceptions.InvalidTag if the message was tampered with.
    """
    raw = base64.b64decode(token.encode('utf-8'))
    nonce, ciphertext = raw[:12], raw[12:]         # Split nonce from payload
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')


# ──────────────────────────────────────────────
# File Encryption Helpers
# ──────────────────────────────────────────────

def encrypt_bytes(key: bytes, data: bytes) -> bytes:
    """
    Encrypt raw bytes (e.g., file contents) with AES-256-GCM.
    Returns nonce + ciphertext as raw bytes.
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_bytes(key: bytes, data: bytes) -> bytes:
    """
    Decrypt raw bytes produced by encrypt_bytes().
    """
    nonce, ciphertext = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ──────────────────────────────────────────────
# Key Serialisation (for exchange over SSL socket)
# ──────────────────────────────────────────────

def key_to_b64(key: bytes) -> str:
    """Encode a raw AES key as a base64 string for transmission."""
    return base64.b64encode(key).decode()


def b64_to_key(b64: str) -> bytes:
    """Decode a base64-encoded AES key back to raw bytes."""
    return base64.b64decode(b64.encode())