import sqlite3

# ===============================
# 🔐 USER: Registrasi & Login
# ===============================
def create_user_table():
    conn = sqlite3.connect("tiket.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

def add_user(username, password):
    conn = sqlite3.connect("tiket.db")
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
    conn.commit()
    conn.close()

def get_user(username, password):
    conn = sqlite3.connect("tiket.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = c.fetchone()
    conn.close()
    return user

def get_user_by_username(username):
    conn = sqlite3.connect("tiket.db")
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return user

# ===============================
# 🎟️ PEMESANAN TIKET
# ===============================
def create_ticket_table():
    conn = sqlite3.connect("tiket.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            encrypted_data TEXT,
            signature TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_ticket(user_id, encrypted_data, signature):
    conn = sqlite3.connect("tiket.db")
    c = conn.cursor()
    c.execute("INSERT INTO tickets (user_id, encrypted_data, signature) VALUES (?, ?, ?)", 
              (user_id, encrypted_data, signature))
    conn.commit()
    conn.close()

def get_ticket_by_user_id(user_id):
    conn = sqlite3.connect("tiket.db")
    c = conn.cursor()
    c.execute("SELECT * FROM tickets WHERE user_id = ?", (user_id,))
    ticket = c.fetchone()
    conn.close()
    return ticket

def delete_existing_ticket(user_id):
    conn = sqlite3.connect("tiket.db")
    c = conn.cursor()
    c.execute("DELETE FROM tickets WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

# ===============================
# ❌ PEMBATALAN TIKET
# ===============================
def create_cancellation_table():
    conn = sqlite3.connect("tiket.db")
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS cancellations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            encrypted_log TEXT,
            signature TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_cancellation(user_id, encrypted_log, signature):
    conn = sqlite3.connect("tiket.db")
    c = conn.cursor()
    c.execute("INSERT INTO cancellations (user_id, encrypted_log, signature) VALUES (?, ?, ?)",
              (user_id, encrypted_log, signature))
    conn.commit()
    conn.close()

def get_cancellation_by_user_id(user_id):
    conn = sqlite3.connect("tiket.db")
    c = conn.cursor()
    c.execute("SELECT * FROM cancellations WHERE user_id = ?", (user_id,))
    cancellation = c.fetchone()
    conn.close()
    return cancellation
