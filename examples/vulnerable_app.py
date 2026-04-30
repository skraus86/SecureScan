"""
Example vulnerable application for testing SecureScan
DO NOT USE IN PRODUCTION - This file contains intentional vulnerabilities
"""

import os
import sqlite3
import pickle
import hashlib
import random


# SAST001: SQL Injection
def get_user_unsafe(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: String concatenation in SQL query
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()


# SAST003: Command Injection
def run_command(user_input):
    # Vulnerable: User input passed to system command
    os.system("ls -la " + user_input)


# SAST004: XSS (in template context)
def render_message(message):
    # Vulnerable: Unescaped user input
    return f"<div>{message}</div>"


# SAST006: Hardcoded Password
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz"


# SAST007: Insecure Deserialization
def load_user_data(data):
    # Vulnerable: Deserializing untrusted data
    return pickle.loads(data)


# SAST008: Weak Cryptography
def hash_password(password):
    # Vulnerable: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()


# SAST009: Insecure Random
def generate_token():
    # Vulnerable: Using non-cryptographic random
    return str(random.randint(100000, 999999))


# SAST010: SSRF
def fetch_url(user_url):
    import requests
    # Vulnerable: Fetching user-provided URL
    return requests.get(user_url + "/api/data")


# SAST016: Dangerous eval
def calculate(expression):
    # Vulnerable: Using eval on user input
    return eval(expression)


# SEC012: Database Connection String
MONGO_URI = "mongodb://admin:password123@localhost:27017/mydb"


# SEC017: JWT Token (example - not real)
SAMPLE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"


if __name__ == "__main__":
    print("This is a vulnerable example application")
    print("Run SecureScan to detect the vulnerabilities:")
    print("  python -m securescan examples/")
