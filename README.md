# Password Encryption Tool

This Python tool provides a secure way to encrypt and decrypt passwords using a keyphrase. It comes with both a command-line interface and a graphical user interface.

## How It Works

The tool derives a key from your passphrase using **Argon2id**, the winner of the Password Hashing Competition. Argon2 is a modern, memory-hard key derivation function that offers strong protection against brute-force and GPU-based attacks. The derived key is then used with **Fernet** (AES-128 in CBC mode + HMAC) to encrypt and decrypt the password.

## Installation

To use this tool, you need to have Python 3 and the required libraries installed. You can install the dependencies using pip:

```bash
pip install -r requirements.txt
```

## Usage

You can use the tool in two ways: through the command-line interface or the graphical user interface.

### Graphical User Interface (GUI)

To run the GUI application, execute the `gui_tool.py` script:

```bash
./gui_tool.py
```

The application provides a simple interface to encrypt and decrypt passwords.

### Command-Line Interface (CLI)

The command-line interface is still available for scripting and automation.

#### Encrypt a Password

To encrypt a password, use the `-e` or `--encrypt` flag, followed by the password you want to encrypt. You also need to provide a keyphrase using the `-k` or `--key` flag.

```bash
./encrypt_tool.py -e "YourSecretPassword" -k "YourMasterKey"
```

**Output:**

```
Encrypted token: <saltyt...base64>
```

#### Decrypt a Password

To decrypt a token, use the `-d` or `--decrypt` flag, followed by the encrypted token. You must provide the same keyphrase that was used to encrypt the token.

```bash
./encrypt_tool.py -d "<saltyt...base64>" -k "YourMasterKey"
```

**Output:**

```
Decrypted text: YourSecretPassword
```
