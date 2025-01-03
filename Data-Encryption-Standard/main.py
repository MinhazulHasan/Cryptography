from Crypto.Cipher import DES
import os
import time
import platform
import psutil
import sys

def get_system_specs():
    """Get system specifications"""
    return {
        "OS": platform.system() + " " + platform.release(),
        "Processor": platform.processor(),
        "RAM": f"{psutil.virtual_memory().total / (1024 ** 3):.2f} GB",
        "Python Version": platform.python_version()
    }

def pad_data(data):
    """Pad data to match DES block size (8 bytes)"""
    padding_length = 8 - (len(data) % 8)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def perform_des_operations(input_file, key):
    """Perform DES encryption and decryption on input file and measure time separately"""
    # Convert student ID to 64-bit key (8 bytes)
    key_bytes = key.encode()[:8].ljust(8, b'0')
    
    try:
        # Read file
        file_size = os.path.getsize(input_file)
        chunk_size = 1024 * 1024  # 1MB chunks
        
        # Encryption Phase
        encryption_cipher = DES.new(key_bytes, DES.MODE_ECB)
        encrypted_chunks = []
        
        encryption_start_time = time.time()
        
        with open(input_file, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                    
                # Pad the last chunk if necessary
                if len(chunk) % 8 != 0:
                    chunk = pad_data(chunk)
                
                encrypted_chunk = encryption_cipher.encrypt(chunk)
                encrypted_chunks.append(encrypted_chunk)
        
        encrypted_data = b''.join(encrypted_chunks)
        encryption_time = time.time() - encryption_start_time
        
        # Decryption Phase
        decryption_cipher = DES.new(key_bytes, DES.MODE_ECB)
        decrypted_chunks = []
        
        decryption_start_time = time.time()
        
        # Process encrypted data in chunks
        for i in range(0, len(encrypted_data), chunk_size):
            chunk = encrypted_data[i:i + chunk_size]
            decrypted_chunk = decryption_cipher.decrypt(chunk)
            decrypted_chunks.append(decrypted_chunk)
        
        decrypted_data = b''.join(decrypted_chunks)
        decryption_time = time.time() - decryption_start_time
        
        # Verify decryption (optional)
        with open(input_file, 'rb') as f:
            original_data = f.read()
            if len(original_data) % 8 != 0:
                original_data = pad_data(original_data)
            verification = (original_data == decrypted_data)
        
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
    
    for file_path in files:
        if not os.path.exists(file_path):
            print(f"Error: File not found - {file_path}")
            continue
            
        result = perform_des_operations(file_path, student_id)
        
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
    
    return results

def format_size(size_bytes):
    """Format file size in human readable format"""
    for unit in ['MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} GB"

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
    
    # Print encryption key details
    print("\nEncryption Details:")
    print("-" * 50)
    print(f"Student ID: {STUDENT_ID}")
    print(f"DES Key (hex): {STUDENT_ID.encode()[:8].ljust(8, b'0').hex()}")
    
    # Perform analysis
    print("\nPerforming encryption and decryption analysis...")
    print("-" * 50)
    results = analyze_files(files, STUDENT_ID)
    
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
                  f"{result['encryption_time']:<12.2f} "
                  f"{result['decryption_time']:<12.2f} "
                  f"{result['encryption_speed_mbps']:<16.2f} "
                  f"{result['decryption_speed_mbps']:<16.2f} "
                  f"{'✓' if result['verification'] else '✗':<8}")

if __name__ == "__main__":
    main()