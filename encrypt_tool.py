#!/usr/bin/env python3
"""
A simple tool to encrypt and decrypt passwords using a key.
Requires: pip install cryptography argon2-cffi
"""
import argparse
import sys
from core_encryption import encrypt, decrypt


def main():
    parser = argparse.ArgumentParser(description="Encrypt and decrypt passwords with a key.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', metavar='PASSWORD', help='String to encrypt')
    group.add_argument('-d', '--decrypt', metavar='TOKEN', help='Encrypted token to decrypt')
    parser.add_argument('-k', '--key', required=True, help='Secret key to derive the key from')

    args = parser.parse_args()
    try:
        if args.encrypt:
            result = encrypt(args.encrypt, args.key)
            print(f"Encrypted token: {result}")
        else:
            result = decrypt(args.decrypt, args.key)
            print(f"Decrypted text: {result}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
