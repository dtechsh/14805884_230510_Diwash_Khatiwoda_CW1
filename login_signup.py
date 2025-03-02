import mysql.connector
import bcrypt
import re

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "stegano_users"
}

def connect_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"❌ Error: Unable to connect to MySQL: {err}")
        exit()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(stored_password, entered_password):
    return bcrypt.checkpw(entered_password.encode(), stored_password.encode())

def init_db():
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
    conn.close()

def validate_name(name):
    return bool(re.fullmatch(r"[A-Z][a-z]{1,19}", name))

def validate_gmail(email):
    return bool(re.fullmatch(r"[a-zA-Z0-9._%+-]{4,}@gmail\.com", email))

def validate_username(username):
    return bool(re.fullmatch(r"^(?=.*[\d])(?=.*[\W_])[a-zA-Z\d\W_]{6,25}$", username))

def validate_password(password):
    return bool(re.fullmatch(r"^(?=.*[A-Z])(?=.*[\d])(?=.*[\W_])[A-Za-z\d\W_]{8,30}$", password))

def sign_up():
    conn = connect_db()
    cursor = conn.cursor()

    while True:
        first_name = input("Enter your First Name: ").strip()
        if validate_name(first_name):
            break
        print("❌ Error: First Name must be capitalized and contain only letters (1-20 characters).")

    while True:
        last_name = input("Enter your Last Name: ").strip()
        if validate_name(last_name):
            break
        print("❌ Error: Last Name must be capitalized and contain only letters (1-20 characters).")

    attempt = 0
    while attempt < 2:
        gmail = input("Enter your Gmail: ").strip()
        if validate_gmail(gmail):
            cursor.execute("SELECT COUNT(*) FROM users WHERE gmail = %s", (gmail,))
            if cursor.fetchone()[0] == 0:
                break
            print("❌ Error: Gmail is already registered!")
        else:
            print("❌ Error: Invalid Gmail! It must include '@gmail.com' and have at least 4 characters before '@gmail.com'.")
        attempt += 1
    else:
        conn.close()
        return False

    attempt = 0
    while attempt < 2:
        username = input("Enter a Username (6-25 characters, 1 number, 1 special character): ").strip()
        if validate_username(username):
            cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
            if cursor.fetchone()[0] == 0:
                break
            print("❌ Error: Username already exists!")
        else:
            print("❌ Error: Username must be 6-25 characters long, contain at least one number and one special character.")
        attempt += 1
    else:
        conn.close()
        return False

    attempt = 0
    while attempt < 2:
        password = input("Enter a Password (8-30 characters, 1 uppercase, 1 number, 1 special character): ").strip()
        confirm_password = input("Confirm Password: ").strip()
        if validate_password(password) and password == confirm_password:
            break
        print("❌ Error: Password must be 8-30 characters long, contain at least one uppercase letter, one number, and one special character.")
        attempt += 1
    else:
        conn.close()
        return False

    hashed_pw = hash_password(password)
    cursor.execute("INSERT INTO users (first_name, last_name, gmail, username, password) VALUES (%s, %s, %s, %s, %s)",
                   (first_name, last_name, gmail, username, hashed_pw))
    conn.commit()
    conn.close()

    print("✅ Sign up successful! You can now log in.")
    return True

def login():
    conn = connect_db()
    cursor = conn.cursor()

    username = input("Enter Username: ").strip()
    password = input("Enter Password: ").strip()

    cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if user and verify_password(user[0], password):
        print("✅ Login successful! Access granted.")
        conn.close()
        return True
    else:
        print("❌ Error: Invalid username or password!")
        conn.close()
        return False

def forgot_password():
    conn = connect_db()
    cursor = conn.cursor()

    username = input("Enter your Username: ").strip()
    gmail = input("Enter your Gmail: ").strip()

    cursor.execute("SELECT password FROM users WHERE username = %s AND gmail = %s", (username, gmail))
    user = cursor.fetchone()

    if not user:
        print("❌ Error: Username or Gmail is incorrect!")
        conn.close()
        return False

    old_hashed_password = user[0]

    attempts = 0
    while attempts < 2:
        new_password = input("Enter a New Password (8-30 characters, 1 uppercase, 1 number, 1 special character): ").strip()
        confirm_password = input("Confirm New Password: ").strip()

        if not validate_password(new_password) or new_password != confirm_password:
            print("❌ Error: Password must be 8-30 characters long, contain at least one uppercase letter, one number, and one special character.")
        elif verify_password(old_hashed_password, new_password):
            print("❌ Error: New password cannot be the same as the previous password.")
        else:
            break

        attempts += 1

    if attempts == 2:
        print("❌ Too many failed attempts. Please try again later.")
        conn.close()
        return False

    hashed_pw = hash_password(new_password)
    cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_pw, username))
    conn.commit()
    conn.close()

    print("✅ Password reset successful! You can now log in with your new password.")
    return True

def authentication():
    init_db()

    while True:
        print("\n=== USER AUTHENTICATION ===")
        print("1. Sign Up")
        print("2. Login")
        print("3. Forgot Password")
        print("4. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            sign_up()
        elif choice == "2":
            if login():
                return True
        elif choice == "3":
            forgot_password()
        elif choice == "4":
            print("Exiting...")
            exit()
        else:
            print("❌ Invalid choice! Please enter a valid option.")

