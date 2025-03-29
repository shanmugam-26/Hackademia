from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def init_db():
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        ''')
        # Insert admin user if it doesn't exist
        c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
        if not c.fetchone():
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', 'admin123'))
        conn.commit()

init_db()

home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Bank - Home</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f0f0f0;}
        header {background-color: #0033cc; color: white; padding: 20px; text-align: center;}
        nav a {margin: 0 15px; color: white; text-decoration: none;}
        .content {padding: 20px; text-align: center;}
        footer {background-color: #0033cc; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}
    </style>
</head>
<body>
    <header>
        <h1>Welcome to Secure Bank</h1>
        <nav>
            <a href="{{ url_for('home') }}">Home</a>
            <a href="{{ url_for('register') }}">Register</a>
            <a href="{{ url_for('login') }}">Login</a>
        </nav>
    </header>
    <div class="content">
        <h2>Your Trusted Partner in Banking</h2>
        <p>Experience secure and reliable banking services with Secure Bank.</p>
    </div>
    <footer>
        &copy; 2023 Secure Bank. All rights reserved.
    </footer>
</body>
</html>
'''

register_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Bank - Register</title>
    <style>
        /* styles similar to home_template */
        body {font-family: Arial, sans-serif; background-color: #f0f0f0;}
        header {background-color: #0033cc; color: white; padding: 20px; text-align: center;}
        nav a {margin: 0 15px; color: white; text-decoration: none;}
        .content {padding: 20px;}
        .form-group {margin-bottom: 10px;}
        label {display: block;}
        input {width: 100%; padding: 8px;}
        button {padding: 10px 20px; background-color: #0033cc; color: white; border: none;}
        footer {background-color: #0033cc; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}
    </style>
</head>
<body>
    <header>
        <h1>Secure Bank - Register</h1>
        <nav>
            <a href="{{ url_for('home') }}">Home</a>
            <a href="{{ url_for('register') }}">Register</a>
            <a href="{{ url_for('login') }}">Login</a>
        </nav>
    </header>
    <div class="content">
        <h2>Create a New Account</h2>
        {% if error %}
        <p style="color:red;">{{ error }}</p>
        {% endif %}
        <form method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" name="username" required/>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" name="password" required/>
            </div>
            <button type="submit">Register</button>
        </form>
    </div>
    <footer>
        &copy; 2023 Secure Bank. All rights reserved.
    </footer>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Bank - Login</title>
    <style>
        /* styles similar to register_template */
        body {font-family: Arial, sans-serif; background-color: #f0f0f0;}
        header {background-color: #0033cc; color: white; padding: 20px; text-align: center;}
        nav a {margin: 0 15px; color: white; text-decoration: none;}
        .content {padding: 20px;}
        .form-group {margin-bottom: 10px;}
        label {display: block;}
        input {width: 100%; padding: 8px;}
        button {padding: 10px 20px; background-color: #0033cc; color: white; border: none;}
        footer {background-color: #0033cc; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}
    </style>
</head>
<body>
    <header>
        <h1>Secure Bank - Login</h1>
        <nav>
            <a href="{{ url_for('home') }}">Home</a>
            <a href="{{ url_for('register') }}">Register</a>
            <a href="{{ url_for('login') }}">Login</a>
        </nav>
    </header>
    <div class="content">
        <h2>Login to Your Account</h2>
        {% if error %}
        <p style="color:red;">{{ error }}</p>
        {% endif %}
        <form method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" name="username" required/>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" name="password" required/>
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
    <footer>
        &copy; 2023 Secure Bank. All rights reserved.
    </footer>
</body>
</html>
'''

account_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Bank - Account</title>
    <style>
        /* styles similar to previous templates */
        body {font-family: Arial, sans-serif; background-color: #f0f0f0;}
        header {background-color: #0033cc; color: white; padding: 20px; text-align: center;}
        nav a {margin: 0 15px; color: white; text-decoration: none;}
        .content {padding: 20px;}
        footer {background-color: #0033cc; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}
    </style>
</head>
<body>
    <header>
        <h1>Secure Bank - Account Overview</h1>
        <nav>
            <a href="{{ url_for('home') }}">Home</a>
            <a href="{{ url_for('logout') }}">Logout</a>
        </nav>
    </header>
    <div class="content">
        <h2>Welcome, {{ username }}!</h2>
        <p>Your account balance is $10,000</p>
        <p>For your convenience, your password is: <strong>{{ password }}</strong></p>
        {% if username == 'admin' %}
            <div style="border: 2px solid green; padding: 10px; margin-top: 20px;">
                <h3>Congratulations!</h3>
                <p>You have successfully exploited the vulnerability!</p>
            </div>
        {% endif %}
    </div>
    <footer>
        &copy; 2023 Secure Bank. All rights reserved.
    </footer>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Insecurely store the password (plaintext)
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            try:
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
                conn.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = 'Username already exists!'
    return render_template_string(register_template, error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check credentials
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('SELECT password FROM users WHERE username = ?', (username,))
            result = c.fetchone()
            if result and result[0] == password:
                session['username'] = username
                return redirect(url_for('account'))
            else:
                error = 'Invalid username or password!'
    return render_template_string(login_template, error=error)

@app.route('/account')
def account():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    # Retrieve password (insecurely) to display
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        if result:
            password = result[0]
        else:
            password = ''
    return render_template_string(account_template, username=username, password=password)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)