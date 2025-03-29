from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key'

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    conn.commit()
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'password123'))
        conn.commit()
    conn.close()

def write_templates():
    if not os.path.exists('templates'):
        os.makedirs('templates')
    with open('templates/index.html', 'w') as f:
        f.write('''
<!DOCTYPE html>
<html>
<head>
    <title>Delicious Bites Restaurant</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Welcome to Delicious Bites</h1>
        <p>Your favorite place for delightful meals.</p>
        <a href="{{ url_for('login') }}" class="btn btn-primary">Admin Login</a>
    </div>
</body>
</html>
''')

    with open('templates/login.html', 'w') as f:
        f.write('''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login - Delicious Bites</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h2 class="mt-5">Admin Login</h2>
        {% if error %}
            <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <form method="post" class="mt-3">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" class="form-control"/>
            </div>
            <div class="form-group mt-2">
                <label>Password</label>
                <input type="password" name="password" class="form-control"/>
            </div>
            <button type="submit" class="btn btn-success mt-3">Login</button>
        </form>
    </div>
</body>
</html>
''')

    with open('templates/dashboard.html', 'w') as f:
        f.write('''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard - Delicious Bites</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h2 class="mt-5">Welcome, {{ username }}!</h2>
        {% if username == 'admin' %}
            <p>This is the admin dashboard.</p>
        {% else %}
            <p>Congratulations! You have successfully exploited the vulnerability.</p>
        {% endif %}
    </div>
</body>
</html>
''')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        # Vulnerable to SQL Injection
        query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
        c.execute(query)
        user = c.fetchone()
        conn.close()

        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials'
            return render_template('login.html', error=error)
    return render_template('login.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        return render_template('dashboard.html', username=username)
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)