from flask import Flask, render_template_string, request, redirect, url_for, session, flash
import sqlite3
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a secure random key in production

DATABASE = 'transport.db'

# HTML Templates
index_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SwiftTrans Logistics</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0;}
        .header {background-color: #003366; color: #ffffff; padding: 20px; text-align: center;}
        .nav {overflow: hidden; background-color: #333;}
        .nav a {float: left; display: block; color: #f2f2f2; text-align: center;
                padding: 14px 16px; text-decoration: none;}
        .nav a:hover {background-color: #ddd; color: black;}
        .container {padding: 20px;}
        .footer {background-color: #003366; color: #ffffff; text-align: center;
                 padding: 10px; position: fixed; left: 0; bottom: 0; width: 100%;}
        .btn {background-color: #003366; color: white; padding: 10px 20px;
              border: none; cursor: pointer;}
        .btn:hover {background-color: #555555;}
        .form-container {background-color: #ffffff; padding: 20px; margin: auto;
                         width: 300px; border-radius: 5px;}
        .alert {color: red;}
    </style>
</head>
<body>

<div class="header">
    <h1>Welcome to SwiftTrans Logistics</h1>
    <p>Your trusted partner in transportation services</p>
</div>

<div class="nav">
    <a href="{{ url_for('index') }}">Home</a>
    {% if 'username' in session %}
    <a href="{{ url_for('dashboard') }}">Dashboard</a>
    <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
    <a href="{{ url_for('login') }}">Login</a>
    <a href="{{ url_for('register') }}">Register</a>
    {% endif %}
</div>

<div class="container">
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <ul class="alert">
        {% for message in messages %}
          <li>{{ message }}</li>
        {% endfor %}
        </ul>
      {% endif %}
    {% endwith %}
    <h2>About Us</h2>
    <p>SwiftTrans Logistics offers premier transportation solutions across the country.
       Our state-of-the-art fleet ensures your cargo arrives safely and on time.</p>
    <h3>Our Services</h3>
    <ul>
        <li>Freight Transportation</li>
        <li>Logistics Management</li>
        <li>Supply Chain Solutions</li>
    </ul>
</div>

<div class="footer">
    <p>&copy; {{ year }} SwiftTrans Logistics. All rights reserved.</p>
</div>

</body>
</html>
"""

login_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - SwiftTrans Logistics</title>
    <style>
        /* Include styles from index_html */
    </style>
</head>
<body>

<div class="header">
    <h1>SwiftTrans Logistics</h1>
</div>

<div class="nav">
    <a href="{{ url_for('index') }}">Home</a>
    <a href="{{ url_for('register') }}">Register</a>
</div>

<div class="container">
    <h2>Login</h2>
    <div class="form-container">
        <form method="post">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username" required><br><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password" required><br><br>
            <input type="submit" class="btn" value="Login">
        </form>
    </div>
</div>

<div class="footer">
    <p>&copy; {{ year }} SwiftTrans Logistics. All rights reserved.</p>
</div>

</body>
</html>
"""

register_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register - SwiftTrans Logistics</title>
    <style>
        /* Include styles from index_html */
    </style>
</head>
<body>

<div class="header">
    <h1>SwiftTrans Logistics</h1>
</div>

<div class="nav">
    <a href="{{ url_for('index') }}">Home</a>
    <a href="{{ url_for('login') }}">Login</a>
</div>

<div class="container">
    <h2>Register</h2>
    <div class="form-container">
        <form method="post">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username" required><br><br>
            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password" required><br><br>
            <input type="submit" class="btn" value="Register">
        </form>
    </div>
</div>

<div class="footer">
    <p>&copy; {{ year }} SwiftTrans Logistics. All rights reserved.</p>
</div>

</body>
</html>
"""

dashboard_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - SwiftTrans Logistics</title>
    <style>
        /* Include styles from index_html */
    </style>
</head>
<body>

<div class="header">
    <h1>Welcome, {{ session['username'] }}</h1>
</div>

<div class="nav">
    <a href="{{ url_for('index') }}">Home</a>
    <a href="{{ url_for('logout') }}">Logout</a>
</div>

<div class="container">
    <h2>Dashboard</h2>
    <p>Manage your shipments and track your orders here.</p>
    <p style="color: green;">{{ message }}</p>
</div>

<div class="footer">
    <p>&copy; {{ year }} SwiftTrans Logistics. All rights reserved.</p>
</div>

</body>
</html>
"""

congrats_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <style>
        /* Include styles from index_html */
        .congrats { text-align: center; margin-top: 50px; }
        .congrats h1 { font-size: 50px; color: green; }
    </style>
</head>
<body>

<div class="header">
    <h1>SwiftTrans Logistics</h1>
</div>

<div class="container congrats">
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the vulnerability.</p>
</div>

<div class="footer">
    <p>&copy; {{ year }} SwiftTrans Logistics. All rights reserved.</p>
</div>

</body>
</html>
"""

# Database setup
def init_db():
    conn = sqlite3.connect(DATABASE)
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

# Routes
@app.route('/')
def index():
    return render_template_string(index_html, year=datetime.now().year)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Insecure password storage: passwords stored in plaintext
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?",
                       (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.')
            return redirect(url_for('login'))

    return render_template_string(login_html, year=datetime.now().year)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Insecure password storage: passwords stored in plaintext
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?,?)",
                           (username, password))
            conn.commit()
            conn.close()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))

    return render_template_string(register_html, year=datetime.now().year)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        message = ''
        # Check if the user has exploited the vulnerability
        if 'exploited' in session and session['exploited']:
            message = 'You have unlocked a special achievement!'
        return render_template_string(dashboard_html, year=datetime.now().year, message=message)
    else:
        flash('Please login to access the dashboard.')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))

# Vulnerable route (for security professionals to discover)
@app.route('/admin')
def admin():
    # Simulate an admin page that should be protected
    if 'username' in session and session['username'] == 'admin':
        session['exploited'] = True
        return render_template_string(congrats_html, year=datetime.now().year)
    else:
        flash('Access denied.')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)