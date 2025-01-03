from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import platform
import psutil
import sys
from time import perf_counter

def get_system_specs():
    """Get system specifications"""
    return {
        "OS": platform.system() + " " + platform.release(),
        "Processor": platform.processor(),
        "RAM": f"{psutil.virtual_memory().total / (1024 ** 3):.2f} GB",
        "Python Version": platform.python_version()
    }

def generate_aes_key(student_id):
    """Generate 128-bit (16 bytes) key from student ID"""
    return student_id.encode().ljust(16, b'0')[:16]

def perform_aes_operations(input_file, key, iterations=100):
    """Perform AES encryption and decryption on input file and measure time with higher precision"""
    try:
        # Read the entire file
        with open(input_file, 'rb') as f:
            data = f.read()
        file_size = len(data)

        # Encryption Phase
        encryption_cipher = AES.new(key, AES.MODE_ECB)
        encryption_start_time = perf_counter()

        for _ in range(iterations):
            padded_data = pad(data, AES.block_size)
            encrypted_data = encryption_cipher.encrypt(padded_data)

        encryption_time = (perf_counter() - encryption_start_time) / iterations

        # Decryption Phase
        decryption_cipher = AES.new(key, AES.MODE_ECB)
        decryption_start_time = perf_counter()

        for _ in range(iterations):
            decrypted_padded = decryption_cipher.decrypt(encrypted_data)
            decrypted_data = unpad(decrypted_padded, AES.block_size)

        decryption_time = (perf_counter() - decryption_start_time) / iterations

        # Verify decryption
        verification = (data == decrypted_data)

        return {
            'file_size': file_size,
            'encryption_time': encryption_time,
            'decryption_time': decryption_time,
            'verification': verification
        }

    except Exception as e:
        print(f"Error processing {input_file}: {str(e)}")
        return None

def analyze_files(files, student_id):
    """Analyze encryption and decryption performance for multiple files"""
    results = []
    key = generate_aes_key(student_id)

    for file_path in files:
        if not os.path.exists(file_path):
            print(f"Error: File not found - {file_path}")
            continue

        result = perform_aes_operations(file_path, key)

        if result:
            results.append({
                "file": file_path,
                "size_bytes": result['file_size'],
                "size_mb": result['file_size'] / (1024 * 1024),
                "encryption_time": result['encryption_time'],
                "decryption_time": result['decryption_time'],
                "encryption_speed_mbps": (result['file_size'] / (1024 * 1024)) / result['encryption_time'],
                "decryption_speed_mbps": (result['file_size'] / (1024 * 1024)) / result['decryption_time'],
                "verification": result['verification']
            })

    return results, key.hex()

def format_size(size_mb):
    """Format file size in human-readable format"""
    return f"{size_mb:.2f} MB"

def main():
    # Your student ID
    STUDENT_ID = "0424312042"

    # Files to process
    files = [
        "dummy_file_1mb.txt",
        "dummy_file_100mb.txt",
        "dummy_file_1gb.txt"
    ]

    # Verify files exist
    for file_path in files:
        if not os.path.exists(file_path):
            print(f"Error: File not found - {file_path}")
            sys.exit(1)

    # Get system specifications
    system_specs = get_system_specs()

    # Print system specifications
    print("\nSystem Specifications:")
    print("-" * 50)
    for key, value in system_specs.items():
        print(f"{key}: {value}")

    # Perform analysis and get key
    results, key_hex = analyze_files(files, STUDENT_ID)

    # Print encryption key details
    print("\nEncryption Details:")
    print("-" * 50)
    print(f"Student ID: {STUDENT_ID}")
    print(f"AES-128 Key (hex): {key_hex}")

    # Print results
    if results:
        print("\nResults:")
        print("-" * 120)
        print(f"{'File':<20} {'Size':<12} {'Enc Time(s)':<12} {'Dec Time(s)':<12} "
              f"{'Enc Speed(MB/s)':<16} {'Dec Speed(MB/s)':<16} {'Verified':<8}")
        print("-" * 120)

        for result in results:
            print(f"{os.path.basename(result['file']):<20} "
                f"{format_size(result['size_mb']):<12} "
                f"{result['encryption_time']:<12.6f} "
                f"{result['decryption_time']:<12.6f} "
                f"{result['encryption_speed_mbps']:<16.2f} "
                f"{result['decryption_speed_mbps']:<16.2f} "
                f"{'✓' if result['verification'] else '✗':<8}")


if __name__ == "__main__":
    main()
