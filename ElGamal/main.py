import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import sys
import platform
import psutil
import datetime

def print_separator():
    print("\n" + "="*50 + "\n")

class ElGamalAnalysis:
    def __init__(self, student_id):
        self.student_id = student_id
        self.key_size = 2048
        self.student_id_int = int(student_id)
        print(f"Initializing ElGamal Analysis with Student ID: {student_id}")
        
    def generate_keys(self):
        print("Generating keys...")
        parameters = dh.generate_parameters(generator=2, key_size=self.key_size, 
                                         backend=default_backend())
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        print("Keys generated successfully!")
        return private_key, public_key

    def encrypt_file(self, input_file, output_file, public_key):
        print(f"\nEncrypting file: {input_file}")
        with open(input_file, 'rb') as f:
            data = f.read()
        
        symmetric_key = os.urandom(32)
        iv = os.urandom(16)
        
        shared_key = public_key.public_numbers().y.to_bytes((public_key.key_size + 7) // 8, 
                                                          byteorder='big')
        
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), 
                       backend=default_backend())
        encryptor = cipher.encryptor()
        
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        with open(output_file, 'wb') as f:
            f.write(iv)
            f.write(symmetric_key)
            f.write(encrypted_data)
            
        print(f"File encrypted successfully! Output: {output_file}")
        return len(data)

    def decrypt_file(self, input_file, output_file, private_key):
        print(f"\nDecrypting file: {input_file}")
        with open(input_file, 'rb') as f:
            iv = f.read(16)
            symmetric_key = f.read(32)
            encrypted_data = f.read()
        
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv), 
                       backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
            
        print(f"File decrypted successfully! Output: {output_file}")
        return len(decrypted_data)

    def analyze_performance(self, input_files):
        results = []
        private_key, public_key = self.generate_keys()
        # print_separator()

        for input_file in input_files:
            if os.path.exists(input_file):
                print(f"\nAnalyzing file: {input_file}")
                file_size_mb = os.path.getsize(input_file) / (1024 * 1024)
                print(f"File size: {file_size_mb:.2f} MB")

                encrypted_file = f"encrypted_{os.path.basename(input_file)}"
                decrypted_file = f"decrypted_{os.path.basename(input_file)}"
                
                # Encryption
                # print("\nStarting encryption...")
                start_time = time.time()
                file_size = self.encrypt_file(input_file, encrypted_file, public_key)
                encryption_time = time.time() - start_time
                encryption_throughput = (file_size / (1024 * 1024)) / encryption_time
                # print(f"Encryption time: {encryption_time:.2f} seconds")
                # print(f"Encryption throughput: {encryption_throughput:.2f} MB/s")
                
                # Decryption
                print("\nStarting decryption...")
                start_time = time.time()
                self.decrypt_file(encrypted_file, decrypted_file, private_key)
                decryption_time = time.time() - start_time
                decryption_throughput = (file_size / (1024 * 1024)) / decryption_time
                # print(f"Decryption time: {decryption_time:.2f} seconds")
                # print(f"Decryption throughput: {decryption_throughput:.2f} MB/s")
                
                results.append({
                    'file': input_file,
                    'size_mb': file_size_mb,
                    'encryption_time': encryption_time,
                    'decryption_time': decryption_time,
                    'encryption_throughput_mbps': encryption_throughput,
                    'decryption_throughput_mbps': decryption_throughput
                })
                
                # Clean up
                # print("\nCleaning up temporary files...")
                for temp_file in [encrypted_file, decrypted_file]:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                # print("Cleanup complete!")
                
                # print_separator()

        return results

def print_system_info():
    print("\nSystem Information:")
    print(f"OS: {platform.system()} {platform.version()}")
    print(f"Processor: {platform.processor()}")
    print(f"RAM: {round(psutil.virtual_memory().total / (1024.0 ** 3))} GB")
    print(f"Python Version: {sys.version}")
    print_separator()

def main():
    print("\nElGamal Encryption/Decryption Analysis")
    print("=====================================")
    
    student_id = "0424312042"
    
    # print_system_info()
    
    elgamal = ElGamalAnalysis(student_id)
    
    input_files = [
        # "dummy_file_1mb.txt",      # 1 MB file
        # "dummy_file_100mb.txt",  # 100 MB file (commented out)
        "dummy_file_1gb.txt"     # 1 GB file (commented out)
    ]
    
    results = elgamal.analyze_performance(input_files)
    
    # Final Summary
    print("\nFinal Performance Summary:")
    print("========================")
    for result in results:
        print(f"\nFile: {result['file']}")
        print(f"Size: {result['size_mb']:.2f} MB")
        print(f"Encryption Time: {result['encryption_time']:.2f} seconds")
        print(f"Encryption Throughput: {result['encryption_throughput_mbps']:.2f} MB/s")
        print(f"Decryption Time: {result['decryption_time']:.2f} seconds")
        print(f"Decryption Throughput: {result['decryption_throughput_mbps']:.2f} MB/s")
    
    print("\nAnalysis complete!")

if __name__ == "__main__":
    main()