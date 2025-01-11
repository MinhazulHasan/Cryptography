from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import time

# Define the ECC key generation with student ID embedded
student_id = "0424312042"

def generate_ecc_key():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_data(private_key, public_key, plaintext):
    # Generate the shared key using the private key and the peer's public key
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ECC Encryption",
        backend=default_backend()
    ).derive(shared_key)
    
    # Generate a random IV for AES encryption
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def decrypt_data(private_key, public_key, ciphertext):
    # Generate the shared key using the private key and the peer's public key
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ECC Encryption",
        backend=default_backend()
    ).derive(shared_key)
    
    # Extract the IV and decrypt the ciphertext
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext

# Main workflow
if __name__ == "__main__":
    # Generate ECC keys
    private_key, public_key = generate_ecc_key()

    # Specify the file to encrypt and decrypt
    file_path = "dummy_file_1gb.txt"
    with open(file_path, "rb") as file:
        plaintext = file.read()

    # Encrypt the file data
    start_time = time.time()
    encrypted_data = encrypt_data(private_key, public_key, plaintext)
    encryption_time = time.time() - start_time
    print(f"Encryption completed in {encryption_time:.2f} seconds.")

    # Decrypt the file data
    start_time = time.time()
    decrypted_data = decrypt_data(private_key, public_key, encrypted_data)
    decryption_time = time.time() - start_time
    print(f"Decryption completed in {decryption_time:.2f} seconds.")

    # Verify decryption
    if decrypted_data == plaintext:
        print("Decryption successful, data integrity verified.")
    else:
        print("Decryption failed, data integrity compromised.")
