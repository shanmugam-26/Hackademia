from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
import os
from base64 import b64encode, b64decode

app = Flask(__name__)
app.secret_key = 'random-secret-key'  # Necessary for sessions

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    ''')

    # Add a default admin user
    try:
        admin_password = encrypt_password('adminpass')
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', admin_password))
    except sqlite3.IntegrityError:
        pass  # admin already exists

    conn.commit()
    conn.close()

def encrypt_password(password):
    key = 'S3cr3tK3y'  # Fixed key
    encrypted = ''
    for i in range(len(password)):
        k = key[i % len(key)]
        encrypted += chr(ord(password[i]) ^ ord(k))
    return b64encode(encrypted.encode()).decode()

def decrypt_password(encrypted):
    key = 'S3cr3tK3y'  # Fixed key
    encrypted = b64decode(encrypted).decode()
    decrypted = ''
    for i in range(len(encrypted)):
        k = key[i % len(key)]
        decrypted += chr(ord(encrypted[i]) ^ ord(k))
    return decrypted

@app.route('/')
def home():
    return render_template_string('''
    <html>
    <head>
        <title>Gourmet Restaurant</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            h1 { color: #333; }
            nav { margin-bottom: 20px; }
            a { margin-right: 10px; color: #007BFF; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .content { max-width: 600px; margin: auto; background: white; padding: 20px; }
        </style>
    </head>
    <body>
        <div class="content">
            <h1>Welcome to Gourmet Restaurant</h1>
            <p>The finest dining experience.</p>
            <nav>
                <a href="{{ url_for('home') }}">Home</a>
                <a href="{{ url_for('menu') }}">Menu</a>
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('signup') }}">Sign Up</a>
                <a href="{{ url_for('contact') }}">Contact Us</a>
            </nav>
            <img src="https://via.placeholder.com/600x300" alt="Delicious Food" style="width:100%;"/>
            <p>Experience the best dishes crafted by world-class chefs.</p>
        </div>
    </body>
    </html>
    ''')

@app.route('/menu')
def menu():
    return render_template_string('''
    <html>
    <head>
        <title>Menu - Gourmet Restaurant</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            h1 { color: #333; }
            nav { margin-bottom: 20px; }
            a { margin-right: 10px; color: #007BFF; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .content { max-width: 600px; margin: auto; background: white; padding: 20px; }
            ul { list-style-type: none; padding: 0; }
            li { padding: 5px 0; }
        </style>
    </head>
    <body>
        <div class="content">
            <h1>Our Menu</h1>
            <nav>
                <a href="{{ url_for('home') }}">Home</a>
                <a href="{{ url_for('menu') }}">Menu</a>
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('signup') }}">Sign Up</a>
                <a href="{{ url_for('contact') }}">Contact Us</a>
            </nav>
            <ul>
                <li>Grilled Salmon - $25</li>
                <li>Steak au Poivre - $30</li>
                <li>Roasted Chicken - $20</li>
                <li>Vegetarian Lasagna - $18</li>
                <li>Chocolate Lava Cake - $8</li>
                <li>Crème Brûlée - $8</li>
            </ul>
        </div>
    </body>
    </html>
    ''')

@app.route('/contact')
def contact():
    return render_template_string('''
    <html>
    <head>
        <title>Contact Us - Gourmet Restaurant</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            h1 { color: #333; }
            nav { margin-bottom: 20px; }
            a { margin-right: 10px; color: #007BFF; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .content { max-width: 600px; margin: auto; background: white; padding: 20px; }
            form { display: flex; flex-direction: column; }
            label { margin-top: 10px; }
            input, textarea { padding: 5px; }
            input[type="submit"] { margin-top: 20px; width: 100px; }
        </style>
    </head>
    <body>
        <div class="content">
            <h1>Contact Us</h1>
            <nav>
                <a href="{{ url_for('home') }}">Home</a>
                <a href="{{ url_for('menu') }}">Menu</a>
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('signup') }}">Sign Up</a>
                <a href="{{ url_for('contact') }}">Contact Us</a>
            </nav>
            <form>
                <label>Name:</label>
                <input type="text" name="name"/>
                <label>Email:</label>
                <input type="email" name="email"/>
                <label>Message:</label>
                <textarea name="message"></textarea>
                <input type="submit" value="Send"/>
            </form>
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Check credentials
        username = request.form['username']
        password = request.form['password']

        encrypted_password = encrypt_password(password)

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, encrypted_password))
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password.'

    return render_template_string('''
    <html>
    <head>
        <title>Login - Gourmet Restaurant</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            h1 { color: #333; }
            .content { max-width: 400px; margin: auto; background: white; padding: 20px; }
            form { display: flex; flex-direction: column; }
            label { margin-top: 10px; }
            input { padding: 5px; }
            input[type="submit"] { margin-top: 20px; width: 100px; }
            .error { color: red; }
            nav { margin-bottom: 20px; }
            a { margin-right: 10px; color: #007BFF; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="content">
            <h1>Login</h1>
            <nav>
                <a href="{{ url_for('home') }}">Home</a>
                <a href="{{ url_for('menu') }}">Menu</a>
                <a href="{{ url_for('contact') }}">Contact Us</a>
            </nav>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% endif %}
            <form method="post">
                <label>Username:</label>
                <input type="text" name="username"/>
                <label>Password:</label>
                <input type="password" name="password"/>
                <input type="submit" value="Login"/>
            </form>
            <p>Don't have an account? <a href="{{ url_for('signup') }}">Sign up here</a>.</p>
        </div>
    </body>
    </html>
    ''', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        # Create a new user
        username = request.form['username']
        password = request.form['password']

        encrypted_password = encrypt_password(password)

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, encrypted_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = 'Username already exists.'
            conn.close()
    return render_template_string('''
    <html>
    <head>
        <title>Sign Up - Gourmet Restaurant</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            h1 { color: #333; }
            .content { max-width: 400px; margin: auto; background: white; padding: 20px; }
            form { display: flex; flex-direction: column; }
            label { margin-top: 10px; }
            input { padding: 5px; }
            input[type="submit"] { margin-top: 20px; width: 100px; }
            .error { color: red; }
            nav { margin-bottom: 20px; }
            a { margin-right: 10px; color: #007BFF; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="content">
            <h1>Sign Up</h1>
            <nav>
                <a href="{{ url_for('home') }}">Home</a>
                <a href="{{ url_for('menu') }}">Menu</a>
                <a href="{{ url_for('contact') }}">Contact Us</a>
            </nav>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% endif %}
            <form method="post">
                <label>Username:</label>
                <input type="text" name="username"/>
                <label>Password:</label>
                <input type="password" name="password"/>
                <input type="submit" value="Sign Up"/>
            </form>
            <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a>.</p>
        </div>
    </body>
    </html>
    ''', error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    if session['username'] == 'admin':
        return render_template_string('''
        <html>
        <head>
            <title>Admin Dashboard - Gourmet Restaurant</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
                h1 { color: #333; }
                .content { max-width: 600px; margin: auto; background: white; padding: 20px; }
                nav { margin-bottom: 20px; }
                a { margin-right: 10px; color: #007BFF; text-decoration: none; }
                a:hover { text-decoration: underline; }
                .congrats { font-size: 1.2em; color: green; }
            </style>
        </head>
        <body>
            <div class="content">
                <h1>Admin Dashboard</h1>
                <nav>
                    <a href="{{ url_for('dashboard') }}">Dashboard</a>
                    <a href="{{ url_for('logout') }}">Logout</a>
                </nav>
                <p class="congrats">Congratulations! You have found the hidden admin page.</p>
                <p>Your skills are impressive.</p>
            </div>
        </body>
        </html>
        ''')
    else:
        return render_template_string('''
        <html>
        <head>
            <title>User Dashboard - Gourmet Restaurant</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
                h1 { color: #333; }
                .content { max-width: 600px; margin: auto; background: white; padding: 20px; }
                nav { margin-bottom: 20px; }
                a { margin-right: 10px; color: #007BFF; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <div class="content">
                <h1>Welcome, {{ username }}</h1>
                <nav>
                    <a href="{{ url_for('dashboard') }}">Dashboard</a>
                    <a href="{{ url_for('logout') }}">Logout</a>
                </nav>
                <p>Thank you for visiting our restaurant website.</p>
            </div>
        </body>
        </html>
        ''', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)