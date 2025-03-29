from flask import Flask, render_template_string, request, redirect, url_for, session
import os
from Crypto.Cipher import AES
import base64
import hashlib
import sqlite3

app = Flask(__name__)
app.secret_key = 'secret_key_here'  # This should be random in production

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Add admin user
    admin_password = 'supersecret'
    encrypted_admin_password = encrypt_password(admin_password)
    # Try to insert admin user
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', encrypted_admin_password))
    except sqlite3.IntegrityError:
        # Admin user already exists
        pass
    conn.commit()
    conn.close()

def encrypt_password(password):
    # Using hardcoded key and ECB mode (insecure)
    key = b'This is a key123'  # 16 bytes key
    cipher = AES.new(key, AES.MODE_ECB)
    # Pad password to be multiple of 16 bytes
    password_padded = password + ' ' * (16 - len(password) % 16)
    encrypted = cipher.encrypt(password_padded.encode('utf-8'))
    encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
    return encrypted_b64

def decrypt_password(encrypted_b64):
    key = b'This is a key123'
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = base64.b64decode(encrypted_b64)
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode('utf-8').strip()

@app.route('/')
def index():
    # Main fashion brand page
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Fashionista - Home</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-image: url('https://i.imgur.com/8JZQZ0p.jpg');
            background-size: cover;
            color: white;
        }
        .container {
            margin-top: 100px;
            text-align: center;
        }
        h1 {
            font-size: 64px;
            font-weight: bold;
        }
        p {
            font-size: 24px;
        }
        .btn {
            width: 200px;
            margin: 10px;
            font-size: 18px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Fashionista</h1>
        <p>Your one-stop destination for the latest trends in fashion.</p>
        <a href="{{ url_for('login') }}" class="btn btn-primary">Login</a>
        <a href="{{ url_for('register') }}" class="btn btn-secondary">Register</a>
    </div>
</body>
</html>
    ''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        encrypted_password = encrypt_password(password)
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, encrypted_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username already exists. Please choose another one."
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Fashionista - Register</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        .container {
            margin-top: 100px;
            max-width: 500px;
        }
        h1 {
            text-align: center;
            margin-bottom: 30px;
        }
        .btn {
            width: 100%;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Register at Fashionista</h1>
        <form method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" name="username" class="form-control" required />
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" name="password" class="form-control" required />
            </div>
            <input type="submit" value="Register" class="btn btn-primary"/>
        </form>
    </div>
</body>
</html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user:
            encrypted_password = user[0]
            decrypted_password = decrypt_password(encrypted_password)
            if decrypted_password == password:
                session['username'] = username
                return redirect(url_for('profile'))
        return "Invalid credentials. Please try again."
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Fashionista - Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        .container {
            margin-top: 100px;
            max-width: 500px;
        }
        h1 {
            text-align: center;
            margin-bottom: 30px;
        }
        .btn {
            width: 100%;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login to Fashionista</h1>
        <form method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" name="username" class="form-control" required />
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" name="password" class="form-control" required />
            </div>
            <input type="submit" value="Login" class="btn btn-primary"/>
        </form>
    </div>
</body>
</html>
    ''')

@app.route('/profile')
def profile():
    if 'username' in session:
        return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Fashionista - Profile</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        .container {
            margin-top: 100px;
            text-align: center;
        }
        h1 {
            margin-bottom: 30px;
        }
        .btn {
            width: 200px;
            margin: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome, {{ username }}!</h1>
        <p>This is your profile page.</p>
        <a href="{{ url_for('get_encrypted_password') }}" class="btn btn-info">View Encrypted Password</a>
        <a href="{{ url_for('get_all_encrypted_passwords') }}" class="btn btn-warning">View All Encrypted Passwords</a>
        <a href="{{ url_for('logout') }}" class="btn btn-danger">Logout</a>
    </div>
</body>
</html>
        ''', username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/get_encrypted_password')
def get_encrypted_password():
    if 'username' in session:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
        user = c.fetchone()
        conn.close()
        if user:
            encrypted_password = user[0]
            return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Fashionista - Encrypted Password</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        .container {
            margin-top: 100px;
            text-align: center;
            max-width: 800px;
        }
        p {
            word-wrap: break-word;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Your Encrypted Password</h1>
        <p>{{ encrypted_password }}</p>
        <a href="{{ url_for('profile') }}" class="btn btn-primary">Back to Profile</a>
    </div>
</body>
</html>
            ''', encrypted_password=encrypted_password)
    else:
        return redirect(url_for('login'))

@app.route('/get_all_encrypted_passwords')
def get_all_encrypted_passwords():
    # This route is intentionally vulnerable
    if 'username' in session:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT username, password FROM users')
        users = c.fetchall()
        conn.close()
        user_list = ''
        for user in users:
            user_list += f'<p><strong>{user[0]}</strong>: {user[1]}</p>'
        return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Fashionista - All Encrypted Passwords</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        .container {
            margin-top: 50px;
            max-width: 800px;
        }
        p {
            word-wrap: break-word;
        }
        .btn {
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>All Encrypted Passwords</h1>
        {{ user_list|safe }}
        <a href="{{ url_for('profile') }}" class="btn btn-primary">Back to Profile</a>
    </div>
</body>
</html>
        ''', user_list=user_list)
    else:
        return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'username' in session and session['username'] == 'admin':
        return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Fashionista - Admin</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        .container {
            margin-top: 100px;
            text-align: center;
        }
        h1 {
            color: green;
            font-size: 48px;
        }
        p {
            font-size: 24px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the Insecure Cryptographic Storage vulnerability!</p>
        <p>Your skills are impressive.</p>
    </div>
</body>
</html>
        ''')
    else:
        return "Access Denied"
if __name__ == '__main__':
            init_db()
            app.run(debug=True)