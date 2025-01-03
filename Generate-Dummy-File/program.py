import random
import string

def generate_1gb_file(output_file_path):
    # target_size = 1 * 1024 * 1024 * 1024  # 1GB
    # target_size = 100 * 1024 * 1024  # 100MB
    target_size = 1 * 1024 * 1024  # 1MB
    chunk_size = 1024 * 1024  # Write 1MB at a time
    written_size = 0

    # Characters and numbers to fill the file
    chars = string.ascii_letters + string.digits

    try:
        with open(output_file_path, "w", encoding="utf-8") as file:
            while written_size < target_size:
                # Generate a chunk of random characters
                data = ''.join(random.choices(chars, k=chunk_size))
                file.write(data)
                written_size += chunk_size

        print(f"1GB dummy file created at: {output_file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")


# Example usage
output_file_path = "dummy_file_1mb.txt"
generate_1gb_file(output_file_path)
