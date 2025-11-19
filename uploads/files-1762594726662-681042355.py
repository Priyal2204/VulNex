
"""
very_vulnerable_combined.py

A single-file bundle of obvious vulnerabilities for detection testing only.
DO NOT RUN THIS ON A PUBLIC OR PRODUCTION ENVIRONMENT.
Use in an isolated test VM/container.
"""

# ===== Hardcoded secret =====
API_KEY = "SUPER_SECRET_API_KEY_123456"  # Hardcoded credential — should be secret/rotated

# ===== SQL Injection =====
import sqlite3
def vulnerable_sql_search(q):
    """
    Vulnerable: directly formats user input into SQL query.
    """
    conn = sqlite3.connect(':memory:')
    conn.execute('CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    conn.execute("INSERT INTO users(username,password) VALUES ('admin','adminpass')")
    conn.commit()
    # UNSAFE: string formatting of user input
    query = "SELECT id, username FROM users WHERE username LIKE '%{}%';".format(q)
    cur = conn.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows

# ===== Command Injection =====
import subprocess
def vulnerable_ping(target):
    """
    Vulnerable: concatenating user input into shell command and using shell=True.
    """
    cmd = "ping -c 1 " + target
    # UNSAFE: shell=True with concatenated user input
    subprocess.call(cmd, shell=True)

# ===== Eval (RCE) =====
def vulnerable_eval(user_expr):
    """
    Vulnerable: evaluating untrusted input.
    """
    # UNSAFE: eval on raw user input
    return eval(user_expr)

# ===== Insecure Deserialization =====
import pickle
def vulnerable_deserialize(data_bytes):
    """
    Vulnerable: deserializing untrusted data with pickle.
    """
    # UNSAFE: pickle can execute arbitrary code during unpickling
    obj = pickle.loads(data_bytes)
    return obj

# ===== Insecure File Handling =====
def insecure_write(filename, content):
    """
    Vulnerable: writes to a file using user-supplied filename without sanitization.
    """
    path = Path("/tmp") / filename  # predictable path + no sanitization
    with open(path, "w") as f:
        f.write(content)
    return str(path)

# ===== Reflected XSS-like Response (for web apps) =====
def reflected_html(user_input):
    """
    Returns HTML that includes unsanitized user input (simulates reflected XSS).
    """
    return f"<html><body><h1>Search results</h1><div>Query: {user_input}</div></body></html>"

# ===== Weak Crypto =====
import hashlib
def weak_hash_password(password):
    """
    Vulnerable: using MD5 for password hashing (cryptographically broken).
    """
    return hashlib.md5(password.encode()).hexdigest()

# ===== Demo runner (for local testing only) =====
if __name__ == "__main__":
    print("Hardcoded API_KEY:", API_KEY)
    print("SQL search for 'admin':", vulnerable_sql_search("admin"))
    # The following calls are commented out to avoid accidental execution if someone runs the file.
    # vulnerable_ping("127.0.0.1")
    # print("Eval test:", vulnerable_eval("__import__('os').listdir('.')"))
    # vulnerable_deserialize(b'')  # don't call with untrusted data
    # insecure_write("test.txt", "data")
    print("Reflected HTML sample:", reflected_html("<script>alert('xss')</script>"))
    print("Weak hash for 'password123':", weak_hash_password("password123"))
