from flask import Flask, render_template_string, request, redirect, url_for
import sqlite3

app = Flask(__name__)

DATABASE = 'users.db'

# Create the database and users table if not exists
conn = sqlite3.connect(DATABASE)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')
conn.commit()
conn.close()

# Insecure Cryptographic Storage
def store_user(username, password):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    # Storing password directly without hashing (insecure)
    cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Gourmet Palace</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    </head>
    <body>
    <div class="container">
        <h1 class="mt-5">Welcome to Gourmet Palace</h1>
        <p>Your culinary adventure starts here.</p>
        <a href="{{ url_for('login') }}" class="btn btn-primary">Login</a>
        <a href="{{ url_for('register') }}" class="btn btn-secondary">Register</a>
    </div>
    </body>
    </html>
    ''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        store_user(username, password)
        return redirect(url_for('login'))
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - Gourmet Palace</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    </head>
    <body>
    <div class="container">
        <h2 class="mt-5">Register</h2>
        <form method="post">
            <div class="form-group">
                <label>Username:</label>
                <input class="form-control" type="text" name="username" required/>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input class="form-control" type="password" name="password" required/>
            </div>
            <input class="btn btn-primary" type="submit" value="Register"/>
        </form>
    </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and user[2] == password:
            return redirect(url_for('welcome', username=username))
        else:
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login - Gourmet Palace</title>
                <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            </head>
            <body>
            <div class="container">
                <h2 class="mt-5">Login</h2>
                <p class="text-danger">Invalid username or password</p>
                <form method="post">
                    <div class="form-group">
                        <label>Username:</label>
                        <input class="form-control" type="text" name="username" required/>
                    </div>
                    <div class="form-group">
                        <label>Password:</label>
                        <input class="form-control" type="password" name="password" required/>
                    </div>
                    <input class="btn btn-primary" type="submit" value="Login"/>
                </form>
            </div>
            </body>
            </html>
            ''')
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Gourmet Palace</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    </head>
    <body>
    <div class="container">
        <h2 class="mt-5">Login</h2>
        <form method="post">
            <div class="form-group">
                <label>Username:</label>
                <input class="form-control" type="text" name="username" required/>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input class="form-control" type="password" name="password" required/>
            </div>
            <input class="btn btn-primary" type="submit" value="Login"/>
        </form>
    </div>
    </body>
    </html>
    ''')

@app.route('/welcome/<username>')
def welcome(username):
    # When the user is successfully logged in
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Welcome - Gourmet Palace</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    </head>
    <body>
    <div class="container">
        <h2 class="mt-5">Welcome, {{ username }}!</h2>
        <p>Thank you for logging in.</p>
    </div>
    </body>
    </html>
    ''', username=username)

@app.route('/congratulations')
def congratulations():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Congratulations!</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    </head>
    <body>
    <div class="container">
        <h2 class="mt-5">Congratulations!</h2>
        <p>You have successfully exploited the vulnerability.</p>
    </div>
    </body>
    </html>
    ''')
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)