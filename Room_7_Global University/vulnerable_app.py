from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Create table users
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Insert admin user with known password 'admin123' hashed with MD5
    admin_password = 'admin123'
    hashed_admin_password = hashlib.md5(admin_password.encode()).hexdigest()
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', hashed_admin_password))
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global University</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f3f3f3; }
            .nav { background-color: #004080; color: #fff; padding: 10px; }
            .nav a { color: #fff; margin: 0 10px; text-decoration: none; }
            .content { padding: 20px; }
            .footer { background-color: #004080; color: #fff; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
        </style>
    </head>
    <body>
        <div class="nav">
            <a href="{{ url_for('index') }}">Home</a>
            {% if 'username' in session %}
            <span>Welcome, {{ session['username'] }}</span>
            <a href="{{ url_for('logout') }}">Logout</a>
            {% else %}
            <a href="{{ url_for('login') }}">Login</a>
            <a href="{{ url_for('register') }}">Register</a>
            {% endif %}
        </div>
        <div class="content">
            <h1>Welcome to Global University</h1>
            <p>At Global University, we provide world-class education to students all over the globe.</p>
            <p>Your future starts here.</p>
        </div>
        <div class="footer">
            &copy; 2023 Global University. All rights reserved.
        </div>
    </body>
    </html>
    ''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Insecure hash using MD5
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            error = 'Username already exists'
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - Global University</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f3f3f3; }
            .container { width: 300px; margin: 0 auto; padding-top: 100px; }
            .error { color: red; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Register</h1>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% endif %}
            <form method="post" action="{{ url_for('register') }}">
                <p>Username:<br><input type="text" name="username" required></p>
                <p>Password:<br><input type="password" name="password" required></p>
                <p><input type="submit" value="Register"></p>
            </form>
            <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a>.</p>
        </div>
    </body>
    </html>
    ''', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password'
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Global University</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f3f3f3; }
            .container { width: 300px; margin: 0 auto; padding-top: 100px; }
            .error { color: red; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Login</h1>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% endif %}
            <form method="post" action="{{ url_for('login') }}">
                <p>Username:<br><input type="text" name="username" required></p>
                <p>Password:<br><input type="password" name="password" required></p>
                <p><input type="submit" value="Login"></p>
            </form>
            <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a>.</p>
        </div>
    </body>
    </html>
    ''', error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        if username == 'admin':
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Admin Dashboard - Global University</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f3f3f3; }
                    .content { padding: 20px; }
                </style>
            </head>
            <body>
                <div class="content">
                    <h1>Admin Dashboard</h1>
                    <p>Welcome, {{ username }}!</p>
                    <p>Congratulations! You have successfully exploited the Insecure Cryptographic Storage vulnerability.</p>
                </div>
            </body>
            </html>
            ''', username=username)
        else:
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Dashboard - Global University</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f3f3f3; }
                    .content { padding: 20px; }
                </style>
            </head>
            <body>
                <div class="content">
                    <h1>Student Dashboard</h1>
                    <p>Welcome, {{ username }}!</p>
                    <p>Here you can access your courses and materials.</p>
                </div>
            </body>
            </html>
            ''', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)