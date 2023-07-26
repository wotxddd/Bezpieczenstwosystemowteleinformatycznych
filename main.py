from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pkcs1_15

#generowanie kluczy RSA
def generate_rsa_keys(bits):
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

#szyfruje plik
def encrypt_file(file_path, public_key):
    with open(file_path, 'rb') as file:
        data = file.read()

    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    encrypted_data = cipher.encrypt(data)

    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

#deszyfruje plik
def decrypt_file(file_path, private_key):
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    decrypted_data = cipher.decrypt(encrypted_data)

    with open(file_path[:-4] + '_decrypted', 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

#tworzenie podpisu cyfrowego
def create_digital_signature(file_path, private_key):
    with open(file_path, 'rb') as file:
        data = file.read()

    key = RSA.import_key(private_key)
    h = SHA256.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return signature

#weryfikacja podpisu cyfrowego
def verify_digital_signature(file_path, public_key, signature):
    with open(file_path, 'rb') as file:
        data = file.read()

    key = RSA.import_key(public_key)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        print("Podpis cyfrowy jest poprawny.")
    except (ValueError, TypeError):
        print("Podpis cyfrowy jest niepoprawny.")

if __name__ == "__main__":
    bits = 1024
    # zmiena liczby bitów/długość klucza RSA

    public_key, private_key = generate_rsa_keys(bits)

    print("Klucz publiczny:")
    print(public_key.decode())  #konwersja z bajtów do napisu

    print("\nKlucz prywatny:")
    print(private_key.decode())  #konwersja z bajtów do napisu

    # Przykład szyfrowania i deszyfrowania pliku
    file_to_encrypt = 'example.txt'
    encrypt_file(file_to_encrypt, public_key)
    decrypt_file(file_to_encrypt + '.enc', private_key)

    # Przykład podpisywania cyfrowego i weryfikacji podpisu
    file_to_sign = 'example.txt'
    signature = create_digital_signature(file_to_sign, private_key)
    verify_digital_signature(file_to_sign, public_key, signature)
