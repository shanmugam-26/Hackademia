from flask import Flask, render_template_string, request, redirect, url_for, flash
import sqlite3

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Initialize the database
def init_db():
    conn = sqlite3.connect('healthcare.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')  # Insecure storage of passwords (plaintext)
    # Insert an admin user with a weak password
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'admin123'))
    except sqlite3.IntegrityError:
        pass  # User already exists
    conn.commit()
    conn.close()

init_db()

# Templates
index_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CareFirst Health Solutions</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">CareFirst Health Solutions</a>
</nav>
<div class="container">
    <h1 class="mt-5">Welcome to CareFirst Health Solutions</h1>
    <p>Your trusted partner in healthcare.</p>
    <a href="{{ url_for('register') }}" class="btn btn-primary">Register</a>
    <a href="{{ url_for('login') }}" class="btn btn-secondary">Login</a>
</div>
</body>
</html>
'''

register_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register - CareFirst Health Solutions</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Patient Registration</h2>
    {% if error %}
    <div class="alert alert-danger" role="alert">
        {{ error }}
    </div>
    {% endif %}
    <form method="post">
        <div class="form-group">
            <label for="username">Email address</label>
            <input type="email" class="form-control" id="username" name="username" aria-describedby="emailHelp" required>
            <small id="emailHelp" class="form-text text-muted">We'll send appointment reminders to this email.</small>
        </div>
        <div class="form-group">
            <label for="password">Desired Password</label>
            <input type="password" class="form-control" id="password" name="password" required>
            <small class="form-text text-muted">Choose a strong password to protect your account.</small>
        </div>
        <button type="submit" class="btn btn-primary">Register Now</button>
    </form>
</div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - CareFirst Health Solutions</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Patient Login</h2>
    {% if error %}
    <div class="alert alert-danger" role="alert">
        {{ error }}
    </div>
    {% endif %}
    <form method="post">
        <div class="form-group">
            <label for="username">Email address</label>
            <input type="email" class="form-control" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="password">Your Password</label>
            <input type="password" class="form-control" id="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary">Access Account</button>
    </form>
</div>
</body>
</html>
'''

profile_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - CareFirst Health Solutions</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Hello, {{ username | e }}</h2>
    <p>Welcome to your patient dashboard.</p>
</div>
</body>
</html>
'''

congrats_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #e9ecef;
        }
        .congrats-box {
            margin-top: 100px;
            padding: 50px;
            background-color: #fff;
            border-radius: 10px;
            text-align: center;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="congrats-box">
        <h2>Congratulations!</h2>
        <p>You have successfully exploited the Insecure Cryptographic Storage vulnerability.</p>
        <p>Your expertise helps make applications more secure.</p>
    </div>
</div>
</body>
</html>
'''

# Routes
@app.route('/')
def index():
    return render_template_string(index_template)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Insecurely store the password (plaintext)
        conn = sqlite3.connect('healthcare.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.rollback()
            error = 'An account with this email already exists.'
        finally:
            conn.close()
    return render_template_string(register_template, error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Insecure authentication check
        conn = sqlite3.connect('healthcare.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            if username == 'admin':
                return redirect(url_for('congratulations'))
            return render_template_string(profile_template, username=username)
        else:
            error = 'Invalid email or password.'
    return render_template_string(login_template, error=error)

@app.route('/congratulations')
def congratulations():
    return render_template_string(congrats_template)
if __name__ == '__main__':
    app.run(debug=True)