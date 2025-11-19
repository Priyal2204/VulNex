from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/users')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Vulnerable SQL query: user_id is directly concatenated
    query = f"SELECT * FROM users WHERE id = {user_id}" 
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return str(user)

if __name__ == '__main__':
    app.run(debug=True)