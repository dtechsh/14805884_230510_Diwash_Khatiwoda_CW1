import numpy as np
import cv2
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from login_signup import authentication


def message_to_binary(message):
    return ''.join(format(ord(char), '08b') for char in message)

def binary_to_message(binary_str):
    chars = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
    return ''.join(chr(int(b, 2)) for b in chars)

def encrypt_message(message, key):
    try:
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        return base64.b64encode(cipher.iv + encrypted_bytes).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_message(encrypted_message, key):
    try:
        raw = base64.b64decode(encrypted_message)
        iv = raw[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode()
    except Exception as e:
        print("Error: Incorrect decryption key or corrupted data.")
        return None

def embed_message_in_image(img, key, message):
    encrypted_data = encrypt_message(message, key)
    if encrypted_data is None:
        return None
    header = format(len(encrypted_data), '032b')
    encrypted_data_bin = message_to_binary(encrypted_data)
    full_message_bin = header + encrypted_data_bin
    max_capacity = img.size
    if len(full_message_bin) > max_capacity:
        print("Error: Insufficient space in the image. Use a larger image or a shorter message.")
        return None
    flat_img = img.flatten()
    bits = np.array(list(full_message_bin), dtype=np.uint8) - ord('0')
    try:
        flat_img[:len(bits)] = (flat_img[:len(bits)] & np.uint8(254)) | bits
    except Exception as e:
        print(f"Error during encoding: {e}")
        return None
    stego_img = flat_img.reshape(img.shape)
    return stego_img

def extract_message_from_image(img, key):
    flat_img = img.flatten()
    bits = flat_img & 1
    total_bits = bits.size
    if total_bits < 32:
        print("Error: Not enough data in image.")
        return None
    header_bits = bits[:32]
    header_str = ''.join(str(b) for b in header_bits)
    encrypted_length = int(header_str, 2)
    required_bits = 32 + encrypted_length * 8
    if total_bits < required_bits:
        print("Error: Insufficient data for the encoded message.")
        return None
    encrypted_bits = bits[32:required_bits]
    encrypted_bin_str = ''.join(str(b) for b in encrypted_bits)
    encrypted_message = binary_to_message(encrypted_bin_str)
    decrypted_message = decrypt_message(encrypted_message, key)
    return decrypted_message

def check_single_file(file_path):
    if ',' in file_path or ';' in file_path:
        print("Error: Please select only one image.")
        return False
    return True

def check_file_size(file_path, max_size_mb=10):
    try:
        size_bytes = os.path.getsize(file_path)
    except Exception as e:
        print(f"Error accessing file size: {e}")
        return False
    size_mb = size_bytes / (1024 * 1024)
    if size_mb > max_size_mb:
        print(f"Error: Image size is {size_mb:.2f} MB. Please select an image less than {max_size_mb} MB for faster processing.")
        return False
    return True

def check_image():
    file_path = input("Enter the path of the image to check: ").strip()
    if not check_single_file(file_path):
        return
    if not os.path.exists(file_path):
        print("Error: File not found.")
        return
    _, ext = os.path.splitext(file_path)
    img_format = ext.lower().strip('.')
    print(f"Image format: {img_format.upper()}")
    if img_format != "png":
        print("Note: For optimal performance, please convert the image to PNG format.")
    try:
        size_bytes = os.path.getsize(file_path)
    except Exception as e:
        print(f"Error accessing file size: {e}")
        return
    size_mb = size_bytes / (1024 * 1024)
    print(f"Image size: {size_mb:.2f} MB")
    if size_mb > 10:
        print("Warning: Image is larger than 10 MB. Processing may take longer.")
    if size_mb > 5:
        print("Warning: File size above 5 MB may result in slower decryption times.")
    img = cv2.imread(file_path)
    if img is None:
        print("Error: Invalid image format or unable to load image.")
        return
    height, width = img.shape[:2]
    channels = 1 if len(img.shape) == 2 else img.shape[2]
    print(f"Image dimensions: {width} x {height} pixels with {channels} channel(s).")

def convert_to_png():
    file_path = input("Enter the path of the image to convert to PNG: ").strip()
    if not check_single_file(file_path):
        return
    if not os.path.exists(file_path):
        print("Error: File not found.")
        return
    _, ext = os.path.splitext(file_path)
    if ext.lower() == '.png':
        print("Error: Image is already in PNG format. Conversion not required.")
        return
    if not check_file_size(file_path):
        return
    img = cv2.imread(file_path)
    if img is None:
        print("Error: Invalid image format or unable to load image.")
        return
    
    default_output_path = os.path.join(os.path.dirname(file_path), "converted_image.png")
    
    output_path = input(f"Enter the full path (including filename) to save the converted PNG image [Default: {default_output_path}]: ").strip()
    
    if not output_path:
        output_path = default_output_path
    
    if not output_path.lower().endswith('.png'):
        print("Error: Output file must have a .png extension.")
        return
    if os.path.exists(output_path):
        print("Error: File already exists. Choose a different name.")
        return
    try:
        compression_level = 6
        cv2.imwrite(output_path, img, [cv2.IMWRITE_PNG_COMPRESSION, compression_level])
        print(f"Image successfully converted to PNG format as {output_path}")
    except Exception as e:
        print(f"Error during conversion: {e}")


def get_confirmed_key(key_type="encryption"):
    max_attempts = 3
    for attempt in range(max_attempts):
        key1 = input(f"Enter a 16-character {key_type} key: ").strip()
        if len(key1) != 16:
            print("Error: Key must be exactly 16 characters long. Please try again.")
            continue
        key2 = input(f"Confirm the {key_type} key: ").strip()
        if key1 != key2:
            print("Error: Keys do not match. Please try again.")
            continue
        return key1.encode()
    print("Error: Maximum attempts reached. Terminating.")
    return None

def encode_message_in_image():
    file_path = input("Enter the path of the image to encode the message: ").strip()
    if not check_single_file(file_path):
        return
    if not os.path.exists(file_path):
        print("Error: File not found.")
        return
    if not check_file_size(file_path):
        return
    img = cv2.imread(file_path)
    if img is None:
        print("Error: Invalid image format or unable to load image.")
        return
    key = get_confirmed_key("encryption")
    if key is None:
        return
    data = input("Enter the data to be encoded in the image: ").strip()
    if not data:
        print("Error: No data entered.")
        return
    stego_img = embed_message_in_image(img, key, data)
    if stego_img is None:
        return
    
    default_output_path = os.path.join(os.path.dirname(file_path), "stego.png")
    
    output_path = input(f"Enter the full path (including filename) to save the new stego image [Default: {default_output_path}]: ").strip()
    
    if not output_path:
        output_path = default_output_path
    
    if not output_path.lower().endswith('.png'):
        print("Error: Output file must have a .png extension.")
        return
    if os.path.exists(output_path):
        print("Error: File already exists. Choose a different name.")
        return
    try:
        cv2.imwrite(output_path, stego_img)
        print(f"Data successfully encoded into {output_path}")
    except Exception as e:
        print(f"Error saving image: {e}")


def decode_message_from_image():
    file_path = input("Enter the path of the image to decode the message from: ").strip()
    if not check_single_file(file_path):
        return
    if not os.path.exists(file_path):
        print("Error: File not found.")
        return
    if not check_file_size(file_path):
        return
    img = cv2.imread(file_path)
    if img is None:
        print("Error: Invalid image format or unable to load image.")
        return
    key = get_confirmed_key("decryption")
    if key is None:
        return
    message = extract_message_from_image(img, key)
    if message is not None:
        print("\nDecoded message:", message)

def img_steg():
    while True:
        print("\nIMAGE STEGANOGRAPHY OPERATIONS")
        print("1. Check image (size, dimensions)")
        print("2. Convert image to PNG")
        print("3. Encode a message in image")
        print("4. Decode a message from image")
        print("5. Exit")
        choice = input("Enter your choice: ").strip()
        if choice == '1':
            check_image()
        elif choice == '2':
            convert_to_png()
        elif choice == '3':
            encode_message_in_image()
        elif choice == '4':
            decode_message_from_image()
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice! Please enter a number between 1 and 5.")

if __name__ == "__main__":
    if authentication():
        print("Access granted to Steganography Tool.")
        img_steg()
    else:
        print("Access denied.")
