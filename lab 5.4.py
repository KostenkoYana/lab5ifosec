import os
import csv
import random
import string
from cryptography.fernet import Fernet
from tkinter import *
from tkinter import messagebox, simpledialog
import pyperclip
import hashlib
import base64
import bcrypt

# Constants
USERS_FILE = 'users.csv'
PASSWORDS_DIR = 'passwords/'

# Generate a key for AES encryption
def generate_key():
    return Fernet.generate_key()

# Load the key from a file
def load_key():
    with open("secret.key", "rb") as key_file:
        return key_file.read()

# Save the key to a file
def save_key(key):
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Encrypt the file
def encrypt_file(file_name, key):
    fernet = Fernet(key)
    with open(file_name, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_name, "wb") as file:
        file.write(encrypted_data)

# Decrypt the file
def decrypt_file(file_name, key):
    fernet = Fernet(key)
    with open(file_name, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_name, "wb") as file:
        file.write(decrypted_data)

# Initialize file
FILE_NAME = "passwords.csv"
KEY_FILE = "secret.key"

def initialize_file():
    if not os.path.exists(KEY_FILE):
        key = generate_key()
        save_key(key)
    else:
        key = load_key()

    if not os.path.exists(FILE_NAME):
        with open(FILE_NAME, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["Title", "Password", "URL/Application", "Other Information"])
    else:
        try:
            decrypt_file(FILE_NAME, key)
        except Exception as e:
            messagebox.showerror("Error", "Failed to decrypt file. Creating a new one.")
            os.remove(FILE_NAME)
            with open(FILE_NAME, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["Title", "Password", "URL/Application", "Other Information"])

def save_file():
    encrypt_file(FILE_NAME, load_key())

initialize_file()

# Password generation
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    password_entry.delete(0, END)
    password_entry.insert(0, password)

# Copy to clipboard
def copy_to_clipboard(password):
    pyperclip.copy(password)
    messagebox.showinfo("Copied", "Password copied to clipboard")

# Registration and Login
def register_user():
    username = simpledialog.askstring("Registration", "Enter a username:")
    if username:
        password = simpledialog.askstring("Registration", "Enter a password:", show='*')
        if password:
            hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            with open(USERS_FILE, 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([username, hashed_password.decode()])
            os.makedirs(PASSWORDS_DIR, exist_ok=True)
            messagebox.showinfo("Registration", "User registered successfully!")

def login():
    username = simpledialog.askstring("Login", "Enter your username:")
    if username:
        password = simpledialog.askstring("Login", "Enter your password:", show='*')
        if password and validate_user(username, password):
            user_file = f"{PASSWORDS_DIR}{username}_passwords.csv.enc"
            salt = load_or_generate_salt(username)
            key = get_fernet_key(password, salt)
            passwords = load_passwords(key, user_file)
            main_window(username, key, passwords)
        else:
            messagebox.showerror("Login", "Invalid username or password.")

# Validate user
def validate_user(username, password):
    with open(USERS_FILE, newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == username and bcrypt.checkpw(password.encode(), row[1].encode()):
                return True
    return False

# Load or generate salt
def load_or_generate_salt(username):
    salt_file = f"{PASSWORDS_DIR}{username}_salt"
    if os.path.exists(salt_file):
        with open(salt_file, "rb") as file:
            return file.read()
    else:
        salt = os.urandom(16)
        with open(salt_file, "wb") as file:
            file.write(salt)
        return salt

# Get Fernet key
def get_fernet_key(password, salt):
    kdf = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(kdf)

# Load passwords
def load_passwords(key, file_name):
    try:
        decrypt_file(file_name, key)
        with open(file_name, newline='') as file:
            reader = csv.reader(file)
            return list(reader)
    except Exception:
        return []

# GUI Setup
root = Tk()
root.title("Password Manager")

# Entry Fields
title_entry = Entry(root, width=50)
password_entry = Entry(root, width=50)
url_entry = Entry(root, width=50)
info_entry = Entry(root, width=50)

# Labels
Label(root, text="Title").grid(row=0, column=0)
Label(root, text="Password").grid(row=1, column=0)
Label(root, text="URL/Application").grid(row=2, column=0)
Label(root, text="Other Information").grid(row=3, column=0)

title_entry.grid(row=0, column=1)
password_entry.grid(row=1, column=1)
url_entry.grid(row=2, column=1)
info_entry.grid(row=3, column=1)

# Save New Password
def save_password():
    fernet = Fernet(load_key())
    encrypted_password = fernet.encrypt(password_entry.get().encode()).decode()
    
    with open(FILE_NAME, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([title_entry.get(), encrypted_password, url_entry.get(), info_entry.get()])
    title_entry.delete(0, END)
    password_entry.delete(0, END)
    url_entry.delete(0, END)
    info_entry.delete(0, END)
    messagebox.showinfo("Success", "Password Saved")

# Buttons
Button(root, text="Save", command=save_password).grid(row=4, column=1, pady=10)

# Search, Update, and Delete Functions
def search_password():
    title = simpledialog.askstring("Search", "Enter title")
    with open(FILE_NAME, newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == title:
                show_password(row[1])
                return
    messagebox.showinfo("Not Found", "No password found with that title")

def update_password():
    title = simpledialog.askstring("Update", "Enter title")
    updated_password = simpledialog.askstring("Update", "Enter new password")
    rows = []
    fernet = Fernet(load_key())
    encrypted_password = fernet.encrypt(updated_password.encode()).decode()
    
    with open(FILE_NAME, newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == title:
                row[1] = encrypted_password
            rows.append(row)
    with open(FILE_NAME, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(rows)
    messagebox.showinfo("Success", "Password Updated")

def delete_password():
    title = simpledialog.askstring("Delete", "Enter title")
    rows = []
    with open(FILE_NAME, newline='') as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] != title:
                rows.append(row)
    with open(FILE_NAME, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(rows)
    messagebox.showinfo("Success", "Password Deleted")

def show_password(encrypted_password):
    fernet = Fernet(load_key())
    decrypted_password = fernet.decrypt(encrypted_password.encode()).decode()
    
    show_button = Button(root, text="Show", command=lambda: messagebox.showinfo("Password", decrypted_password))
    show_button.grid(row=6, column=1, pady=10)
    copy_button = Button(root, text="Copy", command=lambda: copy_to_clipboard(decrypted_password))
    copy_button.grid(row=7, column=1, pady=10)

Button(root, text="Search", command=search_password).grid(row=5, column=0, pady=10)
Button(root, text="Update", command=update_password).grid(row=5, column=1, pady=10)
Button(root, text="Delete", command=delete_password).grid(row=5, column=2, pady=10)

Button(root, text="Generate Password", command=generate_password).grid(row=4, column=2, pady=10)
Button(root, text="Register", command=register_user).grid(row=8, column=0, pady=10)
Button(root, text="Login", command=login).grid(row=8, column=2, pady=10)

# Handle application close
def on_closing():
    save_file()
    root.destroy()

Button(root, text="Exit", command=on_closing).grid(row=6, column=1, pady=10)

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
