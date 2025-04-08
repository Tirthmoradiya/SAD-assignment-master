import os
import subprocess
import sqlite3

# Command Injection vulnerability
def execute_command(command):
    os.system(command)  # Command injection vulnerability
    subprocess.call(command, shell=True)  # Another command injection vulnerability

# SQL Injection vulnerability
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)  # SQL injection vulnerability
    
    # Another SQL injection vulnerability using f-strings
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Path Traversal vulnerability
def read_file(filename):
    with open("data/" + filename, "r") as f:  # Path traversal vulnerability
        return f.read()

# Hardcoded Credentials
API_KEY = "1234567890abcdef"
password = "supersecret123"
SECRET = "dont-tell-anyone"
access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

# Insecure Cryptography
import hashlib
import random
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # Insecure hashing
    
# Insecure random number generation
def generate_token():
    return random.randint(1000, 9999)  # Insecure random

# Insecure Deserialization
import pickle
import yaml
def load_object(data):
    return pickle.loads(data)  # Insecure deserialization
    
def load_yaml(data):
    return yaml.load(data)  # Insecure YAML loading without SafeLoader

# SSRF vulnerability
import requests
from urllib.request import urlopen
def fetch_url(url):
    return requests.get(url)  # SSRF vulnerability
    
def another_fetch(url):
    return urlopen(url)  # Another SSRF vulnerability

# XXE vulnerability
import xml.etree.ElementTree as ET
from lxml import etree
def parse_xml(xml_data):
    return ET.parse(xml_data)  # XXE vulnerability
    
# Session management issues
def handle_session(user):
    session = {"user_id": user.id}  # Insecure session management
    cookie = f"user={user.id}"  # Insecure cookie handling

# Evaluation vulnerabilities
def run_code(code_string):
    return eval(code_string)  # Dangerous code execution
    
def execute_python(code_string):
    exec(code_string)  # Dangerous code execution 