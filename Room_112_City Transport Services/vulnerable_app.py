from flask import Flask, render_template_string, request, redirect, url_for, session, g
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

DATABASE = ':memory:'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        # Create users table
        cursor = db.cursor()
        cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        ''')
        # Insert sample users
        cursor.execute("INSERT INTO users (username, password) VALUES ('user1', 'password123')")
        cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'adminpass')")
        db.commit()
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def home():
    return render_template_string('''
    <html>
    <head>
        <title>City Transport Services</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f7f9fc; }
            .container { max-width: 700px; margin: auto; background-color: white; padding: 40px; margin-top: 50px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h1 { text-align: center; color: #007bff; }
            p { font-size: 18px; text-align: center; }
            a { text-decoration: none; color: #007bff; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to City Transport Services</h1>
            <p>Your reliable partner for city commuting and transportation solutions.</p>
            <p><a href="{{ url_for('login') }}">Login</a> to access your personalized dashboard.</p>
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Vulnerable SQL query (SQL Injection)
        query = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            if user:
                session['username'] = user[1]
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid credentials'
        except Exception as e:
            error = 'An error occurred: {}'.format(e)
    return render_template_string('''
    <html>
    <head>
        <title>Login - City Transport Services</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f7f9fc; }
            .container { max-width: 400px; margin: auto; background-color: white; padding: 30px; margin-top: 100px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h2 { text-align: center; color: #007bff; }
            .error { color: red; text-align: center; }
            form { margin-top: 20px; }
            label { font-weight: bold; }
            input[type="text"], input[type="password"] { width: 100%; padding: 8px; margin: 5px 0 15px 0; border: 1px solid #ccc; border-radius: 4px; }
            input[type="submit"] { width: 100%; background-color: #007bff; color: white; padding: 10px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
            input[type="submit"]:hover { background-color: #0056b3; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Login</h2>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% endif %}
            <form method="post">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required/>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required/>
                <input type="submit" value="Login"/>
            </form>
        </div>
    </body>
    </html>
    ''', error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template_string('''
        <html>
        <head>
            <title>Dashboard - City Transport Services</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f7f9fc; }
                .container { max-width: 700px; margin: auto; background-color: white; padding: 40px; margin-top: 50px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                h1 { text-align: center; color: #007bff; }
                p { font-size: 18px; text-align: center; }
                a { text-decoration: none; color: #007bff; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome, {{username}}!</h1>
                <p>This is your dashboard where you can manage your bookings and view schedules.</p>
                {% if username == 'admin' %}
                <p><a href="{{ url_for('admin') }}">Admin Panel</a></p>
                {% endif %}
                <p><a href="{{ url_for('logout') }}">Logout</a></p>
            </div>
        </body>
        </html>
        ''', username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'username' in session and session['username'] == 'admin':
        return render_template_string('''
        <html>
        <head>
            <title>Admin Panel - City Transport Services</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f7f9fc; }
                .container { max-width: 700px; margin: auto; background-color: white; padding: 40px; margin-top: 50px; box-shadow: 0 0 10px rgba(0,0,0,0.1); text-align: center; }
                h1 { color: #28a745; }
                p { font-size: 18px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Congratulations!</h1>
                <p>You have successfully exploited the vulnerability.</p>
            </div>
        </body>
        </html>
        ''')
    else:
        return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)