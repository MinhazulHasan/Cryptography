from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time
import os

def generate_key_with_student_id(student_id):
    # Convert student ID to an integer and ensure it's used in key generation
    id_int = int(student_id)
    key = RSA.generate(1024, e=65537)
    return key

def measure_crypto_time(input_file, key):
    # Create cipher objects for encryption and decryption
    cipher_encrypt = PKCS1_OAEP.new(key.publickey())
    cipher_decrypt = PKCS1_OAEP.new(key)
    
    results = {}
    
    # Measure encryption time
    with open(input_file, 'rb') as f:
        chunk = f.read(86)  # Maximum size for RSA-1024
        
        # Encryption timing
        start_time = time.time()
        encrypted_data = cipher_encrypt.encrypt(chunk)
        end_time = time.time()
        results['encryption_time'] = end_time - start_time
        
        # Decryption timing
        start_time = time.time()
        decrypted_data = cipher_decrypt.decrypt(encrypted_data)
        end_time = time.time()
        results['decryption_time'] = end_time - start_time
        
        # Verify decryption
        results['verified'] = (chunk == decrypted_data)
    
    return results

def main():
    # Generate key using student ID
    student_id = "0424312042"
    key = generate_key_with_student_id(student_id)
    
    # Print key details
    print("RSA Key Details:")
    print("-" * 50)
    print(f"Public Key:\n{key.publickey().export_key().decode()}")
    print(f"\nModulus (n): {key.n}")
    print(f"Public exponent (e): {key.e}")
    print("-" * 50)
    
    # Test files
    files = [
        # "dummy_file_1mb.txt",      # Uncomment/comment as needed
        "dummy_file_100mb.txt",    # Uncomment/comment as needed
        #"dummy_file_1gb.txt",      # Uncomment/comment as needed
    ]
    
    # Measure encryption/decryption time for each file
    print("\nPerformance Analysis:")
    print("-" * 50)
    
    for file in files:
        if os.path.exists(file):
            print(f"\nProcessing file: {file}")
            print(f"File size: {os.path.getsize(file) / (1024*1024):.2f} MB")
            
            try:
                results = measure_crypto_time(file, key)
                print(f"Encryption time: {results['encryption_time']:.4f} seconds")
                print(f"Decryption time: {results['decryption_time']:.4f} seconds")
                print(f"Total processing time: {results['encryption_time'] + results['decryption_time']:.4f} seconds")
                print(f"Verification successful: {results['verified']}")
            except Exception as e:
                print(f"Error processing file: {str(e)}")
        else:
            print(f"\nFile not found: {file}")

if __name__ == "__main__":
    main()