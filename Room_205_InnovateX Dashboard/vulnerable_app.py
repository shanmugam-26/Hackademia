from flask import Flask, render_template_string, request, redirect, url_for, session
from flask_session import Session
import sqlite3

app = Flask(__name__)
app.secret_key = 'VerySecretKey'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Use Bootstrap CSS framework
bootstrap_cdn = 'https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css'

# Initialize the mock database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Create table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT, password TEXT)''')
    # Insert a default user
    c.execute("DELETE FROM users")  # Clear existing users
    c.execute("INSERT INTO users VALUES ('admin','password123')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'username' in session:
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>InnovateX Dashboard</title>
                <link rel="stylesheet" href="{{ bootstrap_cdn }}">
            </head>
            <body>
                <div class="container">
                    <h1>Welcome to InnovateX, {{ session['username'] }}!</h1>
                    <p>Your innovative solutions start here.</p>
                    <a href="{{ url_for('logout') }}" class="btn btn-danger">Logout</a>
                </div>
            </body>
            </html>
        ''', bootstrap_cdn=bootstrap_cdn)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    success = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Broken Authentication vulnerability: SQL Injection susceptibility
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        # Vulnerable query using string formatting
        query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
        c.execute(query)
        user = c.fetchone()
        conn.close()

        if user:
            session['username'] = username
            if username != 'admin' or password != 'password123':
                success = 'Congratulations! You have successfully exploited the vulnerability.'
            return redirect(url_for('index'))
        else:
            error = 'Invalid Credentials. Please try again.'

    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>InnovateX Login</title>
            <link rel="stylesheet" href="{{ bootstrap_cdn }}">
            <style>
                body {
                    background-color: #f8f9fa;
                }
                .login-container {
                    margin-top: 100px;
                }
                .logo {
                    font-size: 50px;
                    font-weight: bold;
                    color: #343a40;
                }
            </style>
        </head>
        <body>
            <div class="container login-container">
                <div class="text-center">
                    <div class="logo">InnovateX</div>
                    <p>Empowering Innovation Through Technology</p>
                </div>
                {% if error %}
                    <div class="alert alert-danger" role="alert">
                        {{ error }}
                    </div>
                {% endif %}
                {% if success %}
                    <div class="alert alert-success" role="alert">
                        {{ success }}
                    </div>
                {% endif %}
                <form method="post">
                    <div class="form-group">
                        <label for="username">Email address</label>
                        <input type="text" class="form-control" name="username" placeholder="Enter email">
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" class="form-control" name="password" placeholder="Password">
                    </div>
                    <button type="submit" class="btn btn-primary btn-block">Login</button>
                </form>
                <p class="text-center mt-3">New to InnovateX? <a href="#">Sign Up</a></p>
            </div>
        </body>
        </html>
    ''', error=error, success=success, bootstrap_cdn=bootstrap_cdn)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Initialize database before the first request
db_initialized = False

@app.before_request
def setup():
    global db_initialized
    if not db_initialized:
        init_db()
        db_initialized = True

if __name__ == '__main__':
    app.run(debug=True)