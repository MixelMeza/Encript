from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import json

# Archivos para guardar datos
PRIVATE_KEY_FILE = "private_key_rsa.pem"
PUBLIC_KEY_FILE = "public_key_rsa.pem"
DATA_FILE = "data_rsa.json"

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
                encryption_algorithm=serialization.NoEncryption()  # Sin cifrado
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
def load_private_key_from_file(filename):
    try:
        with open(filename, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except Exception as e:
        print("Error al cargar la clave privada desde el archivo:", e)
        return None

# Cargar clave pública desde un archivo
def load_public_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

# Cargar clave privada desde una cadena PEM
def load_private_key_from_pem(pem_data):
    try:
        # Normalizar la clave ingresada manualmente
        if not pem_data.startswith("-----BEGIN PRIVATE KEY-----"):
            raise ValueError("La clave privada debe comenzar con '-----BEGIN PRIVATE KEY-----'")
        if not pem_data.endswith("-----END PRIVATE KEY-----"):
            raise ValueError("La clave privada debe terminar con '-----END PRIVATE KEY-----'")

        # Asegurarse de que los saltos de línea sean correctos
        pem_data = "\n".join(pem_data.split())

        return serialization.load_pem_private_key(
            pem_data.encode(),
            password=None,
            backend=default_backend()
        )
    except Exception as e:
        print("Error al cargar la clave privada desde la cadena PEM:", e)
        return None

# Cargar clave pública desde una cadena PEM
def load_public_key_from_pem(pem_data):
    try:
        return serialization.load_pem_public_key(
            pem_data.encode(),
            backend=default_backend()
        )
    except Exception as e:
        print("Error al cargar la clave pública:", e)
        return None

# Cifrar datos con RSA
def encrypt_with_rsa(data, public_key):
    try:
        encrypted_data = public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data
    except Exception as e:
        print("Error al cifrar los datos:", e)
        return None

# Descifrar datos con RSA
def decrypt_with_rsa(encrypted_data, private_key):
    try:
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data.decode()
    except Exception as e:
        print("Error al descifrar los datos:", e)
        return None

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

# Comparar claves
def compare_keys(file_key_path, manual_key):
    try:
        # Cargar clave desde el archivo
        with open(file_key_path, "rb") as key_file:
            file_key = key_file.read().decode()

        # Normalizar la clave manual
        manual_key_normalized = "\n".join(manual_key.split())

        # Comparar claves
        if file_key.strip() == manual_key_normalized.strip():
            print("Las claves son idénticas.")
        else:
            print("Las claves son diferentes.")
            print("\nClave desde el archivo:")
            print(file_key)
            print("\nClave ingresada manualmente:")
            print(manual_key_normalized)
    except Exception as e:
        print("Error al comparar las claves:", e)

# Función principal
if __name__ == "__main__":
    # Cargar claves RSA o generarlas si no existen
    try:
        private_key = load_private_key_from_file(PRIVATE_KEY_FILE)
        public_key = load_public_key_from_pem(open(PUBLIC_KEY_FILE, "r").read())
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
        print("4. Comparar claves")
        print("5. Salir")
        option = input("Opción: ")

        if option == "1":
            # Cifrar
            credit_card_number = input("Ingrese el número de tarjeta de crédito: ")
            public_key_pem = input("Ingrese la clave pública (en formato PEM): ")
            public_key = load_public_key_from_pem(public_key_pem)

            if public_key is None:
                print("Clave pública inválida. Intente nuevamente.")
                continue

            encrypted_data = encrypt_with_rsa(credit_card_number, public_key)

            if encrypted_data is None:
                print("Error al cifrar los datos. Intente nuevamente.")
                continue

            # Guardar datos
            if "encrypted_cards" not in data:
                data["encrypted_cards"] = []  # Crear lista si no existe
            data["encrypted_cards"].append(encrypted_data.hex())
            save_data(data, DATA_FILE)

            # Mostrar resultados
            print("\nResultados del cifrado:")
            print("Número de tarjeta cifrado (RSA):", encrypted_data.hex().replace("a", "/").replace("b", ","))

        elif option == "2":
            # Descifrar
            if "encrypted_cards" not in data or not data["encrypted_cards"]:
                print("No hay tarjetas guardadas para descifrar.")
                continue

            # Mostrar tarjetas cifradas disponibles
            print("\nTarjetas cifradas disponibles:")
            for i, encrypted_card in enumerate(data["encrypted_cards"], start=1):
                print(f"{i}. {encrypted_card.replace('a', '/').replace('b', ',')}")

            # Seleccionar tarjeta para descifrar
            try:
                card_index = int(input("Seleccione el número de la tarjeta a descifrar: ")) - 1
                if card_index < 0 or card_index >= len(data["encrypted_cards"]):
                    print("Selección inválida. Intente nuevamente.")
                    continue
            except ValueError:
                print("Entrada inválida. Intente nuevamente.")
                continue

            encrypted_data = bytes.fromhex(data["encrypted_cards"][card_index])
            print("\nDatos cifrados seleccionados:", encrypted_data)

            print("\nSeleccione cómo cargar la clave privada:")
            print("1. Desde el archivo generado automáticamente")
            private_key_option = input("Opción: ")

            if private_key_option == "1":
                private_key = load_private_key_from_file(PRIVATE_KEY_FILE)
                print("Clave privada cargada desde el archivo.")
            else:
                print("Opción no válida. Intente nuevamente.")
                continue

            if private_key is None:
                print("Clave privada inválida. Intente nuevamente.")
                continue

            decrypted_data = decrypt_with_rsa(encrypted_data, private_key)

            if decrypted_data is None:
                print("Error al descifrar los datos. Intente nuevamente.")
                continue

            # Mostrar resultados
            print("\nResultados del descifrado:")
            print("Número de tarjeta descifrado:", decrypted_data)

        elif option == "3":
            # Mostrar datos guardados
            print("\nDatos guardados:")
            if "encrypted_cards" in data:
                for i, encrypted_card in enumerate(data["encrypted_cards"], start=1):
                    print(f"{i}. {encrypted_card.replace('a', '/').replace('b', ',')}")
            else:
                print("No hay datos disponibles.")

        elif option == "4":
            # Comparar claves
            manual_key = input("Ingrese la clave privada manualmente (en formato PEM): ")
            compare_keys(PRIVATE_KEY_FILE, manual_key)

        elif option == "5":
            # Salir
            print("Saliendo del programa.")
            break

        else:
            print("Opción no válida.")