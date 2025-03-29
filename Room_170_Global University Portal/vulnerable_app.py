from flask import Flask, render_template_string, request, redirect, url_for, session
from flask_session import Session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

DATABASE = 'database.db'

# Initialize the database
def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT,
                                         username TEXT UNIQUE NOT NULL,
                                         password TEXT NOT NULL)''')  # Passwords stored in plaintext
        conn.commit()
        conn.close()

# Home page
@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global University Portal</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/semantic-ui@2.4.2/dist/semantic.min.css">
    </head>
    <body>
    <div class="ui container">
        <h1 class="ui header">Welcome to Global University</h1>
        <p>Your journey to excellence begins here.</p>
        {% if session.get('username') %}
            <div class="ui message">
                Logged in as {{ session['username'] }} | <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        {% else %}
            <a href="{{ url_for('login') }}" class="ui primary button">Login</a>
            <a href="{{ url_for('register') }}" class="ui button">Register</a>
        {% endif %}
    </div>
    </body>
    </html>
    ''')

# Registration page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Insecurely storing the password in plaintext
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists."
        conn.close()
        return redirect(url_for('login'))
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register | Global University</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/semantic-ui@2.4.2/dist/semantic.min.css">
    </head>
    <body>
    <div class="ui container">
        <h2 class="ui header">Register</h2>
        <form class="ui form" method="post">
            <div class="field">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>
            <div class="field">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button class="ui primary button" type="submit">Register</button>
        </form>
    </div>
    </body>
    </html>
    ''')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user and user[0] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return "Invalid username or password."
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login | Global University</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/semantic-ui@2.4.2/dist/semantic.min.css">
    </head>
    <body>
    <div class="ui container">
        <h2 class="ui header">Login</h2>
        <form class="ui form" method="post">
            <div class="field">
                <label>Username</label>
                <input type="text" name="username" required>
            </div>
            <div class="field">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button class="ui primary button" type="submit">Login</button>
        </form>
    </div>
    </body>
    </html>
    ''')

# Dashboard
@app.route('/dashboard')
def dashboard():
    if not session.get('username'):
        return redirect(url_for('login'))
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard | Global University</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/semantic-ui@2.4.2/dist/semantic.min.css">
    </head>
    <body>
    <div class="ui container">
        <h2 class="ui header">Student Dashboard</h2>
        <p>Welcome, {{ session['username'] }}!</p>
        <p><a href="{{ url_for('home') }}">Home</a> | <a href="{{ url_for('logout') }}">Logout</a></p>
    </div>
    </body>
    </html>
    ''')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Congratulations page (to be unlocked upon exploitation)
@app.route('/congratulations')
def congratulations():
    if session.get('congrats'):
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Congratulations!</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/semantic-ui@2.4.2/dist/semantic.min.css">
        </head>
        <body>
        <div class="ui container">
            <h1 class="ui header">Congratulations!</h1>
            <p>You have successfully exploited the vulnerability.</p>
        </div>
        </body>
        </html>
        ''')
    else:
        return redirect(url_for('home'))
if __name__ == '__main__':
            init_db()
            app.run(debug=True, host='0.0.0.0', port=5000)