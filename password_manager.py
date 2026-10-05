import sqlite3
import hashlib
import os
import secrets
import string
import getpass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


DB_NAME = "password_manager.db"
SALT_FILE = "salt.bin"


# =========================
# DATABASE
# =========================

def create_database():
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


# =========================
# MASTER PASSWORD
# =========================

def hash_master_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def setup_master_password():
    if not os.path.exists("master.txt"):
        print("\nCreate your Master Password")

        while True:
            password = getpass.getpass("Enter Master Password: ")
            confirm_password = getpass.getpass("Confirm Master Password: ")

            if password != confirm_password:
                print("Passwords do not match. Try again.\n")
                continue

            if len(password) < 6:
                print("Master Password must be at least 6 characters.\n")
                continue

            hashed_password = hash_master_password(password)

            with open("master.txt", "w") as file:
                file.write(hashed_password)

            print("\nMaster Password created successfully!")
            return password


def login():
    password = getpass.getpass("Enter Master Password: ")

    with open("master.txt", "r") as file:
        saved_password = file.read()

    hashed_password = hash_master_password(password)

    if hashed_password == saved_password:
        print("Login successful!")
        return password

    print("Wrong Master Password!")
    return None


# =========================
# ENCRYPTION
# =========================

def get_encryption_key(master_password):
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)

        with open(SALT_FILE, "wb") as file:
            file.write(salt)
    else:
        with open(SALT_FILE, "rb") as file:
            salt = file.read()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )

    key = kdf.derive(master_password.encode())

    return Fernet(
        __import__("base64").urlsafe_b64encode(key)
    )


# =========================
# PASSWORD GENERATOR
# =========================

def generate_password():
    try:
        length = int(input("Enter password length (8-64): "))

        if length < 8 or length > 64:
            print("Length must be between 8 and 64.")
            return

    except ValueError:
        print("Please enter a valid number.")
        return

    characters = (
        string.ascii_letters +
        string.digits +
        "!@#$%^&*()-_=+"
    )

    password = "".join(
        secrets.choice(characters)
        for _ in range(length)
    )

    print("\nGenerated Password:")
    print(password)


# =========================
# PASSWORD STRENGTH
# =========================

def check_password_strength():
    password = getpass.getpass("Enter password to check: ")

    score = 0

    if len(password) >= 8:
        score += 1

    if len(password) >= 12:
        score += 1

    if any(char.isupper() for char in password):
        score += 1

    if any(char.islower() for char in password):
        score += 1

    if any(char.isdigit() for char in password):
        score += 1

    if any(char in string.punctuation for char in password):
        score += 1

    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    print(f"\nPassword Strength: {strength}")


# =========================
# ADD PASSWORD
# =========================

def add_password(cipher):
    website = input("Enter website: ").strip()
    username = input("Enter username/email: ").strip()

    password = getpass.getpass("Enter password: ")

    encrypted_password = cipher.encrypt(
        password.encode()
    ).decode()

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO credentials
        (website, username, password)
        VALUES (?, ?, ?)
    """, (website, username, encrypted_password))

    connection.commit()
    connection.close()

    print("\nCredential saved successfully!")


# =========================
# VIEW PASSWORDS
# =========================

def view_passwords(cipher):
    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, website, username, password
        FROM credentials
        ORDER BY website
    """)

    records = cursor.fetchall()
    connection.close()

    if not records:
        print("\nNo saved credentials.")
        return

    print("\n========== SAVED CREDENTIALS ==========")

    for record_id, website, username, encrypted_password in records:

        password = cipher.decrypt(
            encrypted_password.encode()
        ).decode()

        print(f"\nID       : {record_id}")
        print(f"Website  : {website}")
        print(f"Username : {username}")
        print(f"Password : {password}")
        print("---------------------------------------")


# =========================
# SEARCH PASSWORD
# =========================

def search_password(cipher):
    website = input("Enter website to search: ").strip()

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT id, website, username, password
        FROM credentials
        WHERE website LIKE ?
    """, (f"%{website}%",))

    records = cursor.fetchall()
    connection.close()

    if not records:
        print("\nNo matching website found.")
        return

    print("\n========== SEARCH RESULT ==========")

    for record_id, website, username, encrypted_password in records:

        password = cipher.decrypt(
            encrypted_password.encode()
        ).decode()

        print(f"\nID       : {record_id}")
        print(f"Website  : {website}")
        print(f"Username : {username}")
        print(f"Password : {password}")


# =========================
# UPDATE PASSWORD
# =========================

def update_password(cipher):
    try:
        record_id = int(input("Enter credential ID: "))
    except ValueError:
        print("Invalid ID.")
        return

    new_password = getpass.getpass(
        "Enter new password: "
    )

    encrypted_password = cipher.encrypt(
        new_password.encode()
    ).decode()

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE credentials
        SET password = ?
        WHERE id = ?
    """, (encrypted_password, record_id))

    connection.commit()

    if cursor.rowcount == 0:
        print("\nCredential not found.")
    else:
        print("\nPassword updated successfully!")

    connection.close()


# =========================
# DELETE PASSWORD
# =========================

def delete_password():
    try:
        record_id = int(input("Enter credential ID: "))
    except ValueError:
        print("Invalid ID.")
        return

    connection = sqlite3.connect(DB_NAME)
    cursor = connection.cursor()

    cursor.execute("""
        DELETE FROM credentials
        WHERE id = ?
    """, (record_id,))

    connection.commit()

    if cursor.rowcount == 0:
        print("\nCredential not found.")
    else:
        print("\nCredential deleted successfully!")

    connection.close()


# =========================
# MAIN MENU
# =========================

def main():
    create_database()

    master_password = setup_master_password()

    if master_password is None:
        master_password = login()

    else:
        print("\nPlease login using your Master Password.")
        master_password = login()

    if master_password is None:
        print("\nAccess denied.")
        return

    cipher = get_encryption_key(master_password)

    while True:

        print("\n")
        print("==========================================")
        print("       SECURE PASSWORD MANAGER")
        print("==========================================")
        print("1. Add Password")
        print("2. View Passwords")
        print("3. Search Password")
        print("4. Update Password")
        print("5. Delete Password")
        print("6. Generate Strong Password")
        print("7. Check Password Strength")
        print("8. Exit")
        print("==========================================")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            add_password(cipher)

        elif choice == "2":
            view_passwords(cipher)

        elif choice == "3":
            search_password(cipher)

        elif choice == "4":
            update_password(cipher)

        elif choice == "5":
            delete_password()

        elif choice == "6":
            generate_password()

        elif choice == "7":
            check_password_strength()

        elif choice == "8":
            print("\nThank you for using Secure Password Manager!")
            break

        else:
            print("\nInvalid choice. Please try again.")


if __name__ == "__main__":
    main()