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
    # Deriva una clave a partir de la contraseña y la sal
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt(password: str, keyphrase: str) -> str:
    salt = os.urandom(16)
    key = derive_key(keyphrase.encode(), salt)
    f = Fernet(key)
    token = f.encrypt(password.encode())
    # Devolvemos salt + token, ambos codificados en base64
    return base64.urlsafe_b64encode(salt + token).decode()


def decrypt(token_b64: str, keyphrase: str) -> str:
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
