#!/usr/bin/env python3
import base64
import os
from cryptography.fernet import Fernet, InvalidToken
from argon2 import low_level

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a key from a password and salt using Argon2id.

    Args:
        password: The password to derive the key from.
        salt: The salt to use for key derivation.

    Returns:
        A URL-safe base64-encoded key.
    """
    key = low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=16,
        memory_cost=102400,
        parallelism=8,
        hash_len=32,
        type=low_level.Type.ID
    )
    return base64.urlsafe_b64encode(key)


def encrypt(password: str, keyphrase: str) -> str:
    """Encrypts a password using a keyphrase.

    Args:
        password: The password to encrypt.
        keyphrase: The keyphrase to derive the encryption key from.

    Returns:
        A URL-safe base64-encoded string containing the salt and the
        encrypted token.
    """
    salt = os.urandom(16)
    key = derive_key(keyphrase.encode(), salt)
    f = Fernet(key)
    token = f.encrypt(password.encode())
    return base64.urlsafe_b64encode(salt + token).decode()


def decrypt(token_b64: str, keyphrase: str) -> str:
    """Decrypts a token using a keyphrase.

    Args:
        token_b64: The base64-encoded token to decrypt.
        keyphrase: The keyphrase to derive the decryption key from.

    Returns:
        The decrypted password.

    Raises:
        ValueError: If the key is incorrect or the data is corrupt.
    """
    try:
        data = base64.urlsafe_b64decode(token_b64.encode())
        salt = data[:16]
        token = data[16:]
        key = derive_key(keyphrase.encode(), salt)
        f = Fernet(key)
        return f.decrypt(token).decode()
    except (InvalidToken, ValueError):
        raise ValueError("Incorrect key or corrupt data")
