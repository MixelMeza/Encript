import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from os import urandom

# Archivos para guardar datos
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
DATA_FILE = "data.json"

# Generar claves RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Guardar clave privada en un archivo
def save_private_key(private_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

# Guardar clave pública en un archivo
def save_public_key(public_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Cargar clave privada desde un archivo
def load_private_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

# Cargar clave pública desde un archivo
def load_public_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

# Cifrar con AES
def encrypt_with_aes(data, aes_key):
    iv = urandom(16)  # Vector de inicialización
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return iv, ciphertext

# Cifrar clave AES con RSA
def encrypt_aes_key_with_rsa(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Descifrar clave AES con RSA
def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    aes_key = private_key.decrypt(
        encrypted_key,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Descifrar con AES
def decrypt_with_aes(iv, ciphertext, aes_key):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Guardar datos en un archivo JSON
def save_data(data, filename):
    with open(filename, "w") as file:
        json.dump(data, file)

# Cargar datos desde un archivo JSON
def load_data(filename):
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# Función principal
if __name__ == "__main__":
    # Cargar claves RSA o generarlas si no existen
    try:
        private_key = load_private_key(PRIVATE_KEY_FILE)
        public_key = load_public_key(PUBLIC_KEY_FILE)
    except FileNotFoundError:
        private_key, public_key = generate_rsa_keys()
        save_private_key(private_key, PRIVATE_KEY_FILE)
        save_public_key(public_key, PUBLIC_KEY_FILE)
        print("Claves RSA generadas y guardadas.")

    # Cargar datos previos
    data = load_data(DATA_FILE)

    while True:
        # Menú de opciones
        print("\nSeleccione una opción:")
        print("1. Cifrar un número de tarjeta de crédito")
        print("2. Descifrar un número de tarjeta de crédito")
        print("3. Mostrar datos guardados")
        print("4. Salir")
        option = input("Opción: ")

        if option == "1":
            # Cifrar
            credit_card_number = input("Ingrese el número de tarjeta de crédito: ")

            # Generar clave AES aleatoria
            aes_key = urandom(32)  # Clave AES de 256 bits

            # Cifrar el número de tarjeta de crédito con AES
            iv, encrypted_data = encrypt_with_aes(credit_card_number, aes_key)

            # Cifrar la clave AES con RSA
            encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

            # Guardar datos
            data["encrypted_data"] = encrypted_data.hex()
            data["encrypted_aes_key"] = encrypted_aes_key.hex()
            data["iv"] = iv.hex()
            save_data(data, DATA_FILE)

            # Mostrar resultados
            print("\nResultados del cifrado:")
            print("Número de tarjeta cifrado (AES):", encrypted_data)
            print("Clave AES cifrada (RSA):", encrypted_aes_key)
            print("Vector de inicialización (IV):", iv)

        elif option == "2":
            # Descifrar
            encrypted_data = input("Ingrese el número de tarjeta cifrado (en bytes, ej. b'...'): ")
            encrypted_data = eval(encrypted_data)  # Convertir directamente a bytes
            encrypted_aes_key = input("Ingrese la clave AES cifrada (en bytes, ej. b'...'): ")
            encrypted_aes_key = eval(encrypted_aes_key)  # Convertir directamente a bytes
            iv = input("Ingrese el vector de inicialización (IV) (en bytes, ej. b'...'): ")
            iv = eval(iv)  # Convertir directamente a bytes

            # Descifrar la clave AES con RSA
            decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

            # Descifrar el número de tarjeta de crédito con AES
            decrypted_data = decrypt_with_aes(iv, encrypted_data, decrypted_aes_key)

            # Mostrar resultados
            print("\nResultados del descifrado:")
            print("Número de tarjeta descifrado:", decrypted_data)

        elif option == "3":
            # Mostrar datos guardados
            print("\nDatos guardados:")
            print("Número de tarjeta cifrado (AES):", data.get("encrypted_data", "No disponible"))
            print("Clave AES cifrada (RSA):", data.get("encrypted_aes_key", "No disponible"))
            print("Vector de inicialización (IV):", data.get("iv", "No disponible"))

        elif option == "4":
            # Salir
            print("Saliendo del programa.")
            break

        else:
            print("Opción no válida.")