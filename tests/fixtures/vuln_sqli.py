import sqlite3

def get_user(user_input):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # VULN001: SQL Injection via string concatenation
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()

def get_user_safe(user_input):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (user_input,))
    return cursor.fetchall()
