from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

DATABASE = 'database.db'

def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        # Insert a default user for testing
        cursor.execute('''
            INSERT INTO users (username, password) VALUES ('admin', 'password123')
        ''')
        conn.commit()
        conn.close()

init_db()

home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>National Security Portal - Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #eaeaea;
        }
        .container {
            width: 400px;
            margin: 100px auto;
            text-align: center;
        }
        h1 {
            color: #003366;
        }
        form {
            background-color: #fff;
            padding: 20px;
            border-radius: 10px;
        }
        input[type=text], input[type=password] {
            width: 90%;
            padding: 10px;
            margin: 10px 0;
        }
        input[type=submit] {
            padding: 10px 20px;
            background-color: #003366;
            color: #fff;
            border: none;
            cursor: pointer;
        }
        input[type=submit]:hover {
            background-color: #002244;
        }
        img {
            width: 100px;
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="http://example.com/seal.png" alt="Government Seal">
        <h1>National Security Portal</h1>
        <p>Authorized Personnel Only</p>
        <form method="post" action="/login">
            <input type="text" name="username" placeholder="Username"/><br/>
            <input type="password" name="password" placeholder="Password"/><br/>
            <input type="submit" value="Login"/>
        </form>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(home_page)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Vulnerable SQL query susceptible to SQL Injection
    query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        # User authenticated successfully
        return redirect(url_for('secret'))
    else:
        # Authentication failed
        return redirect(url_for('index'))

secret_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>National Security Portal - Welcome</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #eaeaea;
            text-align: center;
        }
        h1 {
            color: #003366;
            margin-top: 50px;
        }
        p {
            font-size: 18px;
        }
        img {
            width: 100px;
        }
        .message {
            background-color: #dff0d8;
            color: #3c763d;
            display: inline-block;
            padding: 15px;
            border-radius: 5px;
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <img src="http://example.com/seal.png" alt="Government Seal">
    <h1>Welcome to the National Security Portal</h1>
    <div class="message">
        <p>Congratulations! You have successfully accessed the secure area.</p>
    </div>
</body>
</html>
'''

@app.route('/secret')
def secret():
    return render_template_string(secret_page)

if __name__ == '__main__':
    app.run(debug=True)