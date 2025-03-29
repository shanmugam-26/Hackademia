from flask import Flask, render_template_string, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import sqlite3

app = Flask(__name__)
app.secret_key = 'super-secret-key'

# Configuring database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

# Use Bootstrap CSS
bootstrap_cdn = '''<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">'''

# Templates
login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Elite University - Student Portal Login</title>
    ''' + bootstrap_cdn + '''
    <style>
        body {{
            background-color: #f8f9fa;
        }}
        .login-container {{
            margin-top: 100px;
            max-width: 400px;
            padding: 30px;
            background-color: #ffffff;
            border-radius: 10px;
            box-shadow: 0px 0px 10px 0px #000;
        }}
        .logo {{
            display: block;
            margin-left: auto;
            margin-right: auto;
            width: 50%;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="login-container">
        <img src="https://www.pngkey.com/png/full/207-2074102_graduation-cap-png.png" class="logo">
        <h3 class="text-center">Elite University Portal</h3>
        <form action="/login" method="post">
            <div class="form-group">
                <label>Student ID:</label>
                <input type="text" name="username" class="form-control" placeholder="Enter Student ID"/>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" class="form-control" placeholder="Enter Password"/>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Login</button>
        </form>
        {% if error %}
        <div class="alert alert-danger mt-3" role="alert">
            {{ error }}
        </div>
        {% endif %}
    </div>
</div>
</body>
</html>
'''

welcome_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Elite University Portal</title>
    ''' + bootstrap_cdn + '''
    <style>
        body {{
            background-color: #e9ecef;
        }}
        .welcome-container {{
            margin-top: 100px;
            max-width: 600px;
            padding: 30px;
            background-color: #ffffff;
            border-radius: 10px;
            box-shadow: 0px 0px 10px 0px #000;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="welcome-container text-center">
        <h2>Welcome, {{ username }}!</h2>
        <p>This is the secure student portal of Elite University.</p>
        {% if is_admin %}
        <p class="text-success"><strong>Congratulations! You have bypassed the authentication!</strong></p>
        {% endif %}
    </div>
</div>
</body>
</html>
'''

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Create table if not exists
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Clear the table for a fresh start
    c.execute('DELETE FROM users')
    # Insert a default user
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('student001', 'securepass'))
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'adminpass'))
    conn.commit()
    conn.close()

@app.route('/', methods=['GET'])
def index():
    error = request.args.get('error')
    return render_template_string(login_template, error=error)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Vulnerable code: SQL injection vulnerability
    query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(username, password)

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute(query)
        result = c.fetchone()
    except sqlite3.Error as e:
        result = None
    conn.close()

    if result:
        session['username'] = username
        is_admin = False
        if username == 'admin':
            is_admin = True
        return render_template_string(welcome_template, username=username, is_admin=is_admin)
    else:
        error = 'Invalid credentials. Please try again.'
        return redirect(url_for('index', error=error))
)