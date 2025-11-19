# Minimal Flask app with SQL injection vulnerability (for detection only)
# Run inside an isolated environment. Do NOT expose to the internet.
from flask import Flask, request, g
import sqlite3

app = Flask(__name__)
DB = 'test.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB)
    return db

@app.before_first_request
def init_db():
    db = get_db()
    db.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
    db.execute("INSERT OR IGNORE INTO users(id, username, password) VALUES (1, 'alice', 'alicepwd')")
    db.commit()

@app.route('/search')
def search():
    # Vulnerable: directly formatting user input into SQL (SQL Injection)
    q = request.args.get('q', '')
    query = "SELECT id, username FROM users WHERE username LIKE '%{}%'".format(q)
    cur = get_db().execute(query)
    rows = cur.fetchall()
    return {'results': [{'id': r[0], 'username': r[1]} for r in rows]}

if __name__ == '__main__':
    app.run(port=5000)
