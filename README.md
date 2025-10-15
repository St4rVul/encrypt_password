# Password Encryption Tool

This Python tool provides a secure way to encrypt and decrypt passwords using a keyphrase. It derives a key from your passphrase using PBKDF2 with SHA-256 and a random salt, and then encrypts the password using Fernet (AES-128 in CBC mode + HMAC).

## Installation

To use this tool, you need to have Python 3 and the `cryptography` library installed. You can install the library using pip:

```bash
pip install cryptography
```

## How It Works

The script uses a key derivation function (PBKDF2) to create a secure encryption key from a user-provided keyphrase. This key is then used with the Fernet symmetric encryption system to encrypt and decrypt data. A new random salt is used for each encryption, which helps protect against rainbow table attacks.

## Usage

You can use the tool to either encrypt or decrypt a password.

### Encrypt a Password

To encrypt a password, use the `-e` or `--encrypt` flag, followed by the password you want to encrypt. You also need to provide a keyphrase using the `-k` or `--key` flag.

```bash
./encrypt_tool.py -e "YourSecretPassword" -k "YourMasterKey"
```

**Output:**

```
Encrypted token: <saltyt...base64>
```

### Decrypt a Password

To decrypt a token, use the `-d` or `--decrypt` flag, followed by the encrypted token. You must provide the same keyphrase that was used to encrypt the token.

```bash
./encrypt_tool.py -d "<saltyt...base64>" -k "YourMasterKey"
```

**Output:**

```
Decrypted text: YourSecretPassword
```
