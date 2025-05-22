# encrypt_password
Herramienta creada en python para encriptar password 
# Cifrar
./encrypt_tool.py -e "MiContraseñaSuperSecreta" -k "MiClaveMaestra"
# Salida:
# Token cifrado: <saltyt...base64>

# Descifrar
./encrypt_tool.py -d "<saltyt...base64>" -k "MiClaveMaestra"
# Salida:
# Texto descifrado: MiContraseñaSuperSecreta
