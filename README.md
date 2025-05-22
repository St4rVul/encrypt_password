# encrypt_password
Herramienta creada en python para encriptar password, donde se deriva una clave  segura a partir de tu “passphrase” usando PBKDF2 con SHA-256 y una sal aleatoria. Luego se cifra las password con (Fernet / AES-128 en modo CBC + HMAC).

 
# Cifrar
./encrypt_tool.py -e "MiContraseñaSuperSecreta" -k "MiClaveMaestra"
# Salida:
# Token cifrado: <saltyt...base64>

# Descifrar
./encrypt_tool.py -d "<saltyt...base64>" -k "MiClaveMaestra"
# Salida:
# Texto descifrado: MiContraseñaSuperSecreta
