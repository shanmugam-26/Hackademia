from flask import Flask, render_template_string, request, redirect, url_for, session
import hashlib
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Ensure the database directory exists
if not os.path.exists('static'):
    os.makedirs('static')

DB_PATH = 'static/database.db'

# Initialize the database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Insert an admin user with a weak password hash
    c.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not c.fetchone():
        # Password is 'admin123'
        password_hash = hashlib.md5('admin123'.encode()).hexdigest()
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', password_hash))
    conn.commit()
    conn.close()

init_db()

# Templates
home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Smith & Associates Law Firm</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0;}
        header {background-color: #003366; color: #fff; padding: 20px;}
        nav a {color: #fff; margin: 0 15px; text-decoration: none;}
        .container {padding: 20px;}
        footer {background-color: #003366; color: #fff; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%;}
        .btn {background-color: #003366; color: #fff; padding: 10px 15px; text-decoration: none;}
    </style>
</head>
<body>
    <header>
        <h1>Smith & Associates Law Firm</h1>
        <nav>
            <a href="{{ url_for('home') }}">Home</a>
            <a href="{{ url_for('login') }}">Client Login</a>
            <a href="{{ url_for('register') }}">Register</a>
            <a href="{{ url_for('contact') }}">Contact Us</a>
        </nav>
    </header>
    <div class="container">
        <h2>Welcome to Smith & Associates</h2>
        <p>
            At Smith & Associates, we provide top-notch legal services to our valued clients.
            Our team of experienced attorneys is dedicated to serving your legal needs with professionalism and integrity.
        </p>
        <p>
            <a href="{{ url_for('register') }}" class="btn">Become a Client</a>
        </p>
    </div>
    <footer>
        &copy; 2023 Smith & Associates Law Firm
    </footer>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Client Login - Smith & Associates Law Firm</title>
    <style>
        /* Styles omitted for brevity */
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0;}
        .login-form {width: 300px; margin: 100px auto;}
        input[type=text], input[type=password] {width: 100%; padding: 10px; margin: 5px 0;}
        .btn {background-color: #003366; color: #fff; padding: 10px 15px; width: 100%; border: none;}
        .error {color: red;}
    </style>
</head>
<body>
    <div class="login-form">
        <h2>Client Login</h2>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <form action="{{ url_for('login') }}" method="post">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <input type="submit" value="Login" class="btn">
        </form>
    </div>
</body>
</html>
'''

register_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register - Smith & Associates Law Firm</title>
    <style>
        /* Styles omitted for brevity */
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0;}
        .register-form {width: 300px; margin: 100px auto;}
        input[type=text], input[type=password] {width: 100%; padding: 10px; margin: 5px 0;}
        .btn {background-color: #003366; color: #fff; padding: 10px 15px; width: 100%; border: none;}
        .error {color: red;}
        .success {color: green;}
    </style>
</head>
<body>
    <div class="register-form">
        <h2>Register</h2>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        {% if success %}
            <p class="success">{{ success }}</p>
        {% endif %}
        <form action="{{ url_for('register') }}" method="post">
            <input type="text" name="username" placeholder="Choose a Username" required><br>
            <input type="password" name="password" placeholder="Choose a Password" required><br>
            <input type="submit" value="Register" class="btn">
        </form>
    </div>
</body>
</html>
'''

dashboard_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Client Dashboard - Smith & Associates Law Firm</title>
    <style>
        /* Styles omitted for brevity */
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0;}
        .dashboard {width: 600px; margin: 50px auto;}
        .btn {background-color: #003366; color: #fff; padding: 10px 15px; text-decoration: none;}
    </style>
</head>
<body>
    <div class="dashboard">
        <h2>Welcome, {{ username }}!</h2>
        {% if username == 'admin' %}
            <p>Congratulations! You have successfully exploited the vulnerability.</p>
        {% else %}
            <p>This is your client dashboard. Your case details will appear here.</p>
        {% endif %}
        <p><a href="{{ url_for('logout') }}" class="btn">Logout</a></p>
    </div>
</body>
</html>
'''

contact_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Contact Us - Smith & Associates Law Firm</title>
    <style>
        /* Styles omitted for brevity */
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0;}
        .contact-form {width: 500px; margin: 50px auto;}
        textarea {width: 100%; height: 100px; padding: 10px;}
        input[type=text], input[type=email] {width: 100%; padding: 10px; margin: 5px 0;}
        .btn {background-color: #003366; color: #fff; padding: 10px 15px; border: none;}
    </style>
</head>
<body>
    <div class="contact-form">
        <h2>Contact Us</h2>
        <form action="{{ url_for('contact') }}" method="post">
            <input type="text" name="name" placeholder="Your Name" required><br>
            <input type="email" name="email" placeholder="Your Email" required><br>
            <textarea name="message" placeholder="Your Message"></textarea><br>
            <input type="submit" value="Send" class="btn">
        </form>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password_hash))
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template_string(login_template, error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password_hash))
            conn.commit()
            conn.close()
            success = 'Registration successful! You can now log in.'
        except sqlite3.IntegrityError:
            error = 'Username already exists. Please choose a different one.'
    return render_template_string(register_template, error=error, success=success)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        return render_template_string(dashboard_template, username=username)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    return render_template_string(contact_template)

if __name__ == '__main__':
    app.run(debug=True)