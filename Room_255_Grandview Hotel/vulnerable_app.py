from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Initialize the database
def init_db():
    if not os.path.exists('hotel.db'):
        conn = sqlite3.connect('hotel.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)''')
        c.execute('''INSERT INTO users (username, password) VALUES (?, ?)''', ('admin', 'adminpass'))
        conn.commit()
        conn.close()

init_db()

@app.route('/')
def index():
    return render_template_string(index_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Insecure cryptographic storage: passwords stored in plain text
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('hotel.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template_string(login_html, error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        secret_message = None
        if session['username'] == 'admin':
            secret_message = 'Congratulations! You have discovered the hidden message.'
        return render_template_string(dashboard_html, username=session['username'], secret_message=secret_message)
    else:
        return redirect(url_for('login'))

# HTML Templates
index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grandview Hotel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
<div class="container mt-5">
    <h1 class="text-center">Welcome to Grandview Hotel</h1>
    <p class="text-center">Experience luxury like never before. Please <a href="{{ url_for('login') }}">login</a> to continue.</p>
</div>
</body>
</html>
'''

login_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grandview Hotel - Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
<div class="container mt-5">
    <h2>Login to Your Account</h2>
    {% if error %}
    <div class="alert alert-danger" role="alert">
        {{ error }}
    </div>
    {% endif %}
    <form method="post">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" class="form-control" name="username" required autofocus>
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" class="form-control" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
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
    <title>Grandview Hotel - Dashboard</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
<div class="container mt-5">
    <h2>Welcome, {{ username }}</h2>
    {% if secret_message %}
    <div class="alert alert-success" role="alert">
        {{ secret_message }}
    </div>
    {% else %}
    <p>Explore our exclusive offers and services.</p>
    {% endif %}
</div>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)