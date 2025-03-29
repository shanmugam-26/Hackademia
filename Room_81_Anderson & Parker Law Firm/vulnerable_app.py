from flask import Flask, render_template_string, request, redirect, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash
from os import urandom

app = Flask(__name__)
app.secret_key = urandom(24)

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# HTML Templates
index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Anderson & Parker Law Firm</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .navbar {
            margin-bottom: 30px;
        }
        .container {
            max-width: 700px;
        }
        footer {
            margin-top: 50px;
            padding: 20px 0;
            background-color: #343a40;
            color: #fff;
        }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <a class="navbar-brand" href="/">Anderson & Parker</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample07"
          aria-controls="navbarsExample07" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
</nav>
<div class="container">
    <h1>Welcome to Anderson & Parker Law Firm</h1>
    <p>At Anderson & Parker, we provide top-notch legal services to meet all your needs.</p>
    <a href="/login" class="btn btn-primary">Client Login</a>
    <a href="/register" class="btn btn-secondary">Register</a>
</div>
<footer class="text-center">
    &copy; 2023 Anderson & Parker Law Firm. All rights reserved.
</footer>
</body>
</html>
'''

login_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Client Login - Anderson & Parker</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Client Login</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="alert alert-danger" role="alert">
          {{ messages[0] }}
        </div>
      {% endif %}
    {% endwith %}
    <form method="POST" action="/login">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" class="form-control" name="username" id="username" required>
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" class="form-control" name="password" id="password" required>
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
        <a href="/" class="btn btn-link">Back to Home</a>
    </form>
</div>
</body>
</html>
'''

register_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register - Anderson & Parker</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Register</h2>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="alert alert-info" role="alert">
          {{ messages[0] }}
        </div>
      {% endif %}
    {% endwith %}
    <form method="POST" action="/register">
        <div class="form-group">
            <label for="username">Desired Username</label>
            <input type="text" class="form-control" name="username" id="username" required>
        </div>
        <div class="form-group">
            <label for="password">Desired Password</label>
            <input type="password" class="form-control" name="password" id="password" required>
        </div>
        <button type="submit" class="btn btn-secondary">Register</button>
        <a href="/" class="btn btn-link">Back to Home</a>
    </form>
</div>
</body>
</html>
'''

dashboard_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Client Dashboard - Anderson & Parker</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Welcome, {{ username }}</h2>
    <p>This is your client dashboard. From here, you can access your legal documents and communicate securely with your attorney.</p>
    <a href="/logout" class="btn btn-danger">Logout</a>
</div>
</body>
</html>
'''

congrats_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container text-center">
    <h1 class="mt-5">Congratulations!</h1>
    <p>You have successfully exploited the Insecure Cryptographic Storage vulnerability.</p>
</div>
</body>
</html>
'''

# Routes
@app.route('/')
def index():
    return render_template_string(index_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Insecure cryptographic storage: passwords stored in plaintext
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()

        if result and result[0] == password:
            return render_template_string(dashboard_html, username=username)
        else:
            flash('Invalid credentials. Please try again.')
            return redirect(url_for('login'))
    return render_template_string(login_html)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Store password in plaintext (vulnerability)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose another.')
            return redirect(url_for('register'))
        finally:
            conn.close()
    return render_template_string(register_html)

@app.route('/logout')
def logout():
    return redirect(url_for('index'))

# Hidden route for congratulatory message
@app.route('/congrats')
def congrats():
    return render_template_string(congrats_html)
)