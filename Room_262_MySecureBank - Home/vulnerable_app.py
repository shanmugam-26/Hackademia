from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'super secret key'

# Initialize the database
def init_db():
    conn = sqlite3.connect('bank.db')
    c = conn.cursor()
    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    # Add a default user with an insecurely stored password
    c.execute('SELECT * FROM users WHERE username = ?', ('john_doe',))
    if not c.fetchone():
        # Password is stored in plaintext (insecure cryptographic storage)
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('john_doe', 'password123'))
    conn.commit()
    conn.close()

init_db()

# Home page
@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>MySecureBank - Home</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body { background-color: #f8f9fa; }
            .container { margin-top: 50px; }
            .card { margin-top: 20px; }
            footer { margin-top: 50px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to MySecureBank</h1>
            <p>Your security is our priority.</p>
            <a href="{{ url_for('login') }}" class="btn btn-primary">Login to your account</a>
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title">About MySecureBank</h5>
                    <p class="card-text">At MySecureBank, we offer top-notch banking services with state-of-the-art security measures to protect your assets. Join us today and experience banking like never before.</p>
                </div>
            </div>
        </div>
        <footer>
            <p>&copy; 2023 MySecureBank. All rights reserved.</p>
        </footer>
    </body>
    </html>
    ''')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Connect to the database
        conn = sqlite3.connect('bank.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>MySecureBank - Login</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body { background-color: #f8f9fa; }
            .container { margin-top: 100px; max-width: 400px; }
            footer { margin-top: 50px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Login to Your Account</h2>
            {% if error %}
                <div class="alert alert-danger" role="alert">
                    {{ error }}
                </div>
            {% endif %}
            <form method="post">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" class="form-control" name="username" required/>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" class="form-control" name="password" required/>
                </div>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
        </div>
        <footer>
            <p>&copy; 2023 MySecureBank. All rights reserved.</p>
        </footer>
    </body>
    </html>
    ''', error=error)

# Dashboard page
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>MySecureBank - Dashboard</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body { background-color: #f8f9fa; }
            .container { margin-top: 50px; }
            footer { margin-top: 50px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Welcome, {{ username }}!</h2>
            <p>Account Balance: $10,000</p>
            <p>Recent Transactions:</p>
            <ul>
                <li>Deposit: $5,000</li>
                <li>Withdrawal: $1,000</li>
                <li>Deposit: $6,000</li>
            </ul>
            <a href="{{ url_for('logout') }}" class="btn btn-secondary">Logout</a>
        </div>
        <footer>
            <p>&copy; 2023 MySecureBank. All rights reserved.</p>
        </footer>
    </body>
    </html>
    ''', username=session['username'])

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Secret admin page with insecure cryptographic storage vulnerability
@app.route('/admin')
def admin():
    # Only accessible after exploiting the vulnerability
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>MySecureBank - Admin Panel</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body { background-color: #343a40; color: white; }
            .container { margin-top: 50px; }
            footer { margin-top: 50px; text-align: center; }
            h1 { color: #ffc107; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Congratulations!</h1>
            <p>You have successfully exploited the Insecure Cryptographic Storage vulnerability.</p>
            <p>Please report this finding to the security team.</p>
        </div>
        <footer>
            <p>&copy; 2023 MySecureBank. All rights reserved.</p>
        </footer>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)