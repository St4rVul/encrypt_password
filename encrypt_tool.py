#!/usr/bin/env python3
"""
Herramienta sencilla para cifrar y descifrar contraseñas usando una clave.
Requiere: pip install cryptography
"""
import argparse
import base64
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derives a key from a password and salt using PBKDF2.

    Args:
        password: The password to derive the key from.
        salt: The salt to use for key derivation.

    Returns:
        A URL-safe base64-encoded key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


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
    # Devolvemos salt + token, ambos codificados en base64
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
        raise ValueError("Clave incorrecta o datos corruptos")


def main():
    parser = argparse.ArgumentParser(description="Cifrar y descifrar contraseñas con clave.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', metavar='PASSWORD', help='Cadena a cifrar')
    group.add_argument('-d', '--decrypt', metavar='TOKEN', help='Token cifrado a descifrar')
    parser.add_argument('-k', '--key', required=True, help='Clave secreta para derivar la llave')

    args = parser.parse_args()
    try:
        if args.encrypt:
            result = encrypt(args.encrypt, args.key)
            print(f"Token cifrado: {result}")
        else:
            result = decrypt(args.decrypt, args.key)
            print(f"Texto descifrado: {result}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
