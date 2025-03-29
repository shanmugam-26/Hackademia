from flask import Flask, render_template_string, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import os
import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'users.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )''')
    # Create notes table
    c.execute('''CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        note TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    # Insert a special note for a special user
    c.execute('SELECT id FROM users WHERE username = ?', ('admin',))
    admin = c.fetchone()
    if not admin:
        # Create admin user
        admin_password = hashlib.md5('adminpass'.encode()).hexdigest()
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', admin_password))
        admin_id = c.lastrowid
    else:
        admin_id = admin[0]
    # Insert special encrypted note
    secret_message = 'Congratulations! You have found the secret message.'
    encrypted_secret = encrypt_note(secret_message)
    c.execute('INSERT INTO notes (user_id, note) VALUES (?, ?)', (admin_id, encrypted_secret))
    conn.commit()
    conn.close()

def encrypt_note(note):
    # Insecure encryption using DES in ECB mode with a constant key
    key = b'secret_k'  # 8-byte key for DES
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(note.encode(), DES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode()

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Elite University Portal</title>
        <!-- Include Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
    <div class="container mt-5">
        <h1>Welcome to Elite University Portal</h1>
        <p>Your gateway to exclusive educational resources and personalized content.</p>
        {% if session.get('username') %}
            <p>Logged in as {{ session.get('username') }} | <a href="{{ url_for('logout') }}">Logout</a></p>
            <a href="{{ url_for('dashboard') }}" class="btn btn-primary">Go to Dashboard</a>
        {% else %}
            <p><a href="{{ url_for('login') }}" class="btn btn-primary">Login</a>
            <a href="{{ url_for('register') }}" class="btn btn-secondary">Register</a></p>
        {% endif %}
    </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Using MD5 hash for passwords (Insecure)
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Elite University Portal</title>
        <!-- Include Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
    <div class="container mt-5">
        <h2>Login</h2>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for msg in messages %}
                    <div class="alert alert-danger">{{ msg }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="post">
            <div class="mb-3">
                <label>Username</label>
                <input type="text" name="username" class="form-control" required/>
            </div>
            <div class="mb-3">
                <label>Password</label>
                <input type="password" name="password" class="form-control" required/>
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
            <a href="{{ url_for('register') }}" class="btn btn-link">Register</a>
        </form>
    </div>
    </body>
    </html>
    ''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Using MD5 hash for passwords (Insecure)
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        try:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()
            flash('Registration successful. Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
    return render_template_string(''''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - Elite University Portal</title>
        <!-- Include Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
    <div class="container mt-5">
        <h2>Register</h2>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for msg in messages %}
                    <div class="alert alert-danger">{{ msg }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="post">
            <div class="mb-3">
                <label>Username</label>
                <input type="text" name="username" class="form-control" required/>
            </div>
            <div class="mb-3">
                <label>Password</label>
                <input type="password" name="password" class="form-control" required/>
            </div>
            <button type="submit" class="btn btn-primary">Register</button>
            <a href="{{ url_for('login') }}" class="btn btn-link">Login</a>
        </form>
    </div>
    </body>
    </html>
    ''')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('username'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        note = request.form['note']
        encrypted_note = encrypt_note(note)
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('INSERT INTO notes (user_id, note) VALUES (?, ?)', (session['user_id'], encrypted_note))
        conn.commit()
        conn.close()
        flash('Note saved successfully.')
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT note FROM notes WHERE user_id = ?', (session['user_id'],))
    notes = c.fetchall()
    conn.close()
    return render_template_string(''''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - Elite University Portal</title>
        <!-- Include Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
    <div class="container mt-5">
        <h2>Dashboard</h2>
        <p>Welcome, {{ session.get('username') }} | <a href="{{ url_for('logout') }}">Logout</a></p>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                {% for msg in messages %}
                    <div class="alert alert-success">{{ msg }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="post">
            <div class="mb-3">
                <label>New Note</label>
                <textarea name="note" class="form-control" required></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Save Note</button>
        </form>
        <h3 class="mt-4">Your Notes</h3>
        <ul class="list-group">
            {% for note in notes %}
                <li class="list-group-item">{{ note[0] }}</li>
            {% endfor %}
        </ul>
    </div>
    </body>
    </html>
    ''', notes=notes)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))
if __name__ == '__main__':
        app.jinja_env.autoescape = False
        init_db()
        app.run(debug=True)