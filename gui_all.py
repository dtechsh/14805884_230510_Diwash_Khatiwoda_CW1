import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import numpy as np
import cv2
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import mysql.connector
import bcrypt
import re
import sys

# Constants
FONT = ("Arial", 14)
BUTTON_FONT = ("Arial", 16)
BUTTON_WIDTH = 20
WINDOW_SIZE = "800x600"
BUTTON_BG = "#4CAF50"
BUTTON_FG = "white"
ENTRY_WIDTH = 30
LABEL_BG = "#f0f0f0"
FRAME_BG = "#e0e0e0"

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "stegano_users"
}

# Database Functions
def connect_db():
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="stegano_users",
            auth_plugin='caching_sha2_password'  # Add this line
        )
        return conn
    except mysql.connector.Error as err:
        messagebox.showerror("Error", f"Unable to connect to MySQL: {err}")
        sys.exit(1)
        
def hash_password(password):
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string")
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(stored_password, entered_password):
    if not isinstance(stored_password, str) or not isinstance(entered_password, str):
        raise ValueError("Both stored and entered passwords must be strings")
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_password.encode('utf-8'))

def init_db():
    conn = None
    try:
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            first_name VARCHAR(50) NOT NULL,
                            last_name VARCHAR(50) NOT NULL,
                            gmail VARCHAR(100) UNIQUE NOT NULL,
                            username VARCHAR(50) UNIQUE NOT NULL,
                            password VARCHAR(255) NOT NULL
                        )''')
        conn.commit()
    except mysql.connector.Error as err:
        messagebox.showerror("Error", f"Database initialization failed: {err}")
        sys.exit(1)
    finally:
        if conn and conn.is_connected():
            conn.close()

# Validation Functions
def validate_name(name):
    if not isinstance(name, str):
        return False
    return bool(re.fullmatch(r"[A-Z][a-z]{1,19}", name))

def validate_gmail(email):
    if not isinstance(email, str):
        return False
    return bool(re.fullmatch(r"[a-zA-Z0-9._%+-]{4,}@gmail\.com", email))

def validate_username(username):
    if not isinstance(username, str):
        return False
    return bool(re.fullmatch(r"^(?=.*[\d])(?=.*[\W_])[a-zA-Z\d\W_]{6,25}$", username))

def validate_password(password):
    if not isinstance(password, str):
        return False
    return bool(re.fullmatch(r"^(?=.*[A-Z])(?=.*[\d])(?=.*[\W_])[A-Za-z\d\W_]{8,30}$", password))

# GUI Utility Functions
def create_label_and_entry(parent, label_text, entry_var, show=None):
    label = tk.Label(parent, text=label_text, font=FONT)
    label.pack(pady=10)
    entry = tk.Entry(parent, font=FONT, width=ENTRY_WIDTH, textvariable=entry_var, show=show)
    entry.pack(pady=10)
    return label, entry

def create_button(parent, text, command):
    button = tk.Button(parent, text=text, font=BUTTON_FONT, width=BUTTON_WIDTH, command=command, bg=BUTTON_BG, fg=BUTTON_FG)
    button.pack(pady=20)
    return button

# Authentication Functions
def sign_up():
    def submit_signup():
        first_name = first_name_var.get().strip()
        last_name = last_name_var.get().strip()
        gmail = gmail_var.get().strip()
        username = username_var.get().strip()
        password = password_var.get().strip()
        confirm_password = confirm_password_var.get().strip()

        if not validate_name(first_name):
            messagebox.showerror("Error", "First Name must be capitalized and contain only letters (2-20 characters).")
            return
        if not validate_name(last_name):
            messagebox.showerror("Error", "Last Name must be capitalized and contain only letters (2-20 characters).")
            return
        if not validate_gmail(gmail):
            messagebox.showerror("Error", "Invalid Gmail! Must be at least 4 characters before '@gmail.com'.")
            return
        if not validate_username(username):
            messagebox.showerror("Error", "Username must be 6-25 characters, with at least one number and one special character.")
            return
        if not validate_password(password):
            messagebox.showerror("Error", "Password must be 8-30 characters, with at least one uppercase, one number, and one special character.")
            return
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return

        conn = None
        try:
            hashed_pw = hash_password(password)
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE gmail = %s", (gmail,))
            if cursor.fetchone()[0] > 0:
                messagebox.showerror("Error", "Gmail is already registered!")
                return
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
            if cursor.fetchone()[0] > 0:
                messagebox.showerror("Error", "Username already exists!")
                return

            cursor.execute("INSERT INTO users (first_name, last_name, gmail, username, password) VALUES (%s, %s, %s, %s, %s)",
                           (first_name, last_name, gmail, username, hashed_pw))
            conn.commit()
            messagebox.showinfo("Success", "Sign up successful! You can now log in.")
            signup_window.destroy()
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
        finally:
            if conn and conn.is_connected():
                conn.close()

    signup_window = tk.Toplevel()
    signup_window.title("Sign Up")
    signup_window.geometry(WINDOW_SIZE)

    first_name_var = tk.StringVar()
    last_name_var = tk.StringVar()
    gmail_var = tk.StringVar()
    username_var = tk.StringVar()
    password_var = tk.StringVar()
    confirm_password_var = tk.StringVar()

    create_label_and_entry(signup_window, "First Name:", first_name_var)
    create_label_and_entry(signup_window, "Last Name:", last_name_var)
    create_label_and_entry(signup_window, "Gmail:", gmail_var)
    create_label_and_entry(signup_window, "Username:", username_var)
    create_label_and_entry(signup_window, "Password:", password_var, show="*")
    create_label_and_entry(signup_window, "Confirm Password:", confirm_password_var, show="*")

    create_button(signup_window, "Sign Up", submit_signup)

def login():
    def submit_login():
        username = username_var.get().strip()
        password = password_var.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty!")
            return

        conn = None
        try:
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user and verify_password(user[0], password):
                messagebox.showinfo("Success", "Login successful! Access granted.")
                login_window.destroy()
                img_steg()
            else:
                messagebox.showerror("Error", "Invalid username or password!")
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
        finally:
            if conn and conn.is_connected():
                conn.close()

    login_window = tk.Toplevel()
    login_window.title("Login")
    login_window.geometry(WINDOW_SIZE)

    username_var = tk.StringVar()
    password_var = tk.StringVar()

    create_label_and_entry(login_window, "Username:", username_var)
    create_label_and_entry(login_window, "Password:", password_var, show="*")

    create_button(login_window, "Login", submit_login)

def forgot_password():
    def submit_forgot_password():
        username = username_var.get().strip()
        gmail = gmail_var.get().strip()
        new_password = new_password_var.get().strip()
        confirm_password = confirm_password_var.get().strip()

        if not all([username, gmail, new_password, confirm_password]):
            messagebox.showerror("Error", "All fields must be filled!")
            return

        conn = None
        try:
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute("SELECT password FROM users WHERE username = %s AND gmail = %s", (username, gmail))
            user = cursor.fetchone()

            if not user:
                messagebox.showerror("Error", "Username or Gmail is incorrect!")
                return

            old_hashed_password = user[0]

            if not validate_password(new_password):
                messagebox.showerror("Error", "New password must be 8-30 characters, with at least one uppercase, one number, and one special character.")
                return
            if new_password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match!")
                return
            if verify_password(old_hashed_password, new_password):
                messagebox.showerror("Error", "New password cannot be the same as the previous password!")
                return

            hashed_pw = hash_password(new_password)
            cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_pw, username))
            conn.commit()
            messagebox.showinfo("Success", "Password reset successful! You can now log in with your new password.")
            forgot_password_window.destroy()
        except mysql.connector.Error as err:
            messagebox.showerror("Error", f"Database error: {err}")
        finally:
            if conn and conn.is_connected():
                conn.close()

    forgot_password_window = tk.Toplevel()
    forgot_password_window.title("Forgot Password")
    forgot_password_window.geometry(WINDOW_SIZE)

    username_var = tk.StringVar()
    gmail_var = tk.StringVar()
    new_password_var = tk.StringVar()
    confirm_password_var = tk.StringVar()

    create_label_and_entry(forgot_password_window, "Username:", username_var)
    create_label_and_entry(forgot_password_window, "Gmail:", gmail_var)
    create_label_and_entry(forgot_password_window, "New Password:", new_password_var, show="*")
    create_label_and_entry(forgot_password_window, "Confirm New Password:", confirm_password_var, show="*")

    create_button(forgot_password_window, "Submit", submit_forgot_password)

def authentication():
    init_db()

    def open_sign_up():
        sign_up()

    def open_login():
        login()

    def open_forgot_password():
        forgot_password()

    main_window = tk.Tk()
    main_window.title("User Authentication")
    main_window.geometry(WINDOW_SIZE)

    tk.Label(main_window, text="Welcome! Please select an option.", font=("Arial", 18)).pack(pady=30)

    create_button(main_window, "Sign Up", open_sign_up)
    create_button(main_window, "Login", open_login)
    create_button(main_window, "Forgot Password", open_forgot_password)

    main_window.mainloop()

# Steganography Functions
def img_steg():
    steg_window = tk.Tk()
    steg_window.title("Image Steganography Tool")
    steg_window.geometry(WINDOW_SIZE)
    steg_window.configure(bg=LABEL_BG)

    tk.Label(steg_window, text="IMAGE STEGANOGRAPHY OPERATIONS", font=("Arial", 20), bg=LABEL_BG).pack(pady=20)

    frame = tk.Frame(steg_window, bg=FRAME_BG)
    frame.pack(pady=20)

    def check_image():
        file_path = filedialog.askopenfilename(title="Select Image to Check", filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp")])
        if not file_path:
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found.")
            return
        _, ext = os.path.splitext(file_path)
        img_format = ext.lower().lstrip('.')
        try:
            size_bytes = os.path.getsize(file_path)
            size_mb = size_bytes / (1024 * 1024)
            img = cv2.imread(file_path)
            if img is None:
                messagebox.showerror("Error", "Invalid image format or unable to load image.")
                return
            height, width = img.shape[:2]
            channels = 1 if len(img.shape) == 2 else img.shape[2]
            messagebox.showinfo("Image Info", f"Format: {img_format.upper()}\nSize: {size_mb:.2f} MB\nDimensions: {width}x{height} pixels\nChannels: {channels}")
        except Exception as e:
            messagebox.showerror("Error", f"Error checking image: {e}")

    def convert_to_png():
        file_path = filedialog.askopenfilename(title="Select Image to Convert", filetypes=[("Image files", "*.jpg *.jpeg *.bmp")])
        if not file_path:
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found.")
            return
        _, ext = os.path.splitext(file_path)
        if ext.lower() == '.png':
            messagebox.showerror("Error", "Image is already in PNG format. Conversion not required.")
            return
        try:
            img = cv2.imread(file_path)
            if img is None:
                messagebox.showerror("Error", "Invalid image format or unable to load image.")
                return
            new_file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")], title="Save Converted Image As")
            if not new_file_path:
                return
            compression_level = 6
            success = cv2.imwrite(new_file_path, img, [cv2.IMWRITE_PNG_COMPRESSION, compression_level])
            if success:
                messagebox.showinfo("Success", f"Image successfully converted to PNG format as {new_file_path}")
            else:
                messagebox.showerror("Error", "Failed to save the converted image.")
        except Exception as e:
            messagebox.showerror("Error", f"Error during conversion: {e}")

    def encode_message_in_image():
        file_path = filedialog.askopenfilename(title="Select Image to Encode", filetypes=[("PNG files", "*.png")])
        if not file_path:
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found.")
            return
        try:
            img = cv2.imread(file_path)
            if img is None:
                messagebox.showerror("Error", "Invalid image format or unable to load image.")
                return
            key = simpledialog.askstring("Input", "Enter a 16-character encryption key:")
            if not key or len(key) != 16:
                messagebox.showerror("Error", "Key must be exactly 16 characters long.")
                return
            data = simpledialog.askstring("Input", "Enter the data to be encoded in the image:")
            if not data:
                messagebox.showerror("Error", "No data entered.")
                return

            cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)
            encrypted_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
            encrypted_data = base64.b64encode(cipher.iv + encrypted_bytes).decode('utf-8')
            header = format(len(encrypted_data), '032b')
            encrypted_data_bin = ''.join(format(ord(char), '08b') for char in encrypted_data)
            full_message_bin = header + encrypted_data_bin

            flat_img = img.flatten()
            if len(full_message_bin) > len(flat_img):
                messagebox.showerror("Error", "Message too large for the image!")
                return

            bits = np.array(list(full_message_bin), dtype=np.uint8) - ord('0')
            flat_img[:len(bits)] = (flat_img[:len(bits)] & np.uint8(254)) | bits
            stego_img = flat_img.reshape(img.shape)

            output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")], title="Save Stego Image As")
            if not output_path:
                return
            success = cv2.imwrite(output_path, stego_img)
            if success:
                messagebox.showinfo("Success", f"Data successfully encoded into {output_path}")
            else:
                messagebox.showerror("Error", "Failed to save the stego image.")
        except Exception as e:
            messagebox.showerror("Error", f"Error during encoding: {e}")

    def decode_message_from_image():
        file_path = filedialog.askopenfilename(title="Select Image to Decode", filetypes=[("PNG files", "*.png")])
        if not file_path:
            return
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found.")
            return
        try:
            img = cv2.imread(file_path)
            if img is None:
                messagebox.showerror("Error", "Invalid image format or unable to load image.")
                return
            key = simpledialog.askstring("Input", "Enter the 16-character decryption key:")
            if not key or len(key) != 16:
                messagebox.showerror("Error", "Key must be exactly 16 characters long.")
                return

            flat_img = img.flatten()
            bits = flat_img & 1
            if len(bits) < 32:
                messagebox.showerror("Error", "Image too small to contain a message.")
                return

            header_bits = bits[:32]
            header_str = ''.join(str(b) for b in header_bits)
            encrypted_length = int(header_str, 2)
            required_bits = 32 + encrypted_length * 8

            if required_bits > len(bits):
                messagebox.showerror("Error", "Image does not contain a valid message or is corrupted.")
                return

            encrypted_bits = bits[32:required_bits]
            encrypted_bin_str = ''.join(str(b) for b in encrypted_bits)
            encrypted_message = ''.join(chr(int(encrypted_bin_str[i:i+8], 2)) for i in range(0, len(encrypted_bin_str), 8))

            raw = base64.b64decode(encrypted_message)
            iv = raw[:AES.block_size]
            cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
            decrypted_message = unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode('utf-8')
            messagebox.showinfo("Decoded Message", f"Decoded message: {decrypted_message}")
        except Exception as e:
            messagebox.showerror("Error", f"Error during decoding: {e}")

    create_button(frame, "Check Image", check_image)
    create_button(frame, "Convert to PNG", convert_to_png)
    create_button(frame, "Encode Message", encode_message_in_image)
    create_button(frame, "Decode Message", decode_message_from_image)
    create_button(frame, "Exit", steg_window.destroy)

    steg_window.mainloop()

if __name__ == "__main__":
    authentication()