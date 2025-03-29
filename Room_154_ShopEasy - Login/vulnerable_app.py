from flask import Flask, render_template_string, request, redirect, url_for, session
import hashlib
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

DATABASE = 'database.db'

# Initialize the database
def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        # Create users table with insecure cryptographic storage (storing passwords as MD5 hashes)
        c.execute('''CREATE TABLE users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE NOT NULL,
                      password TEXT NOT NULL)''')
        # Add a default user
        password_hash = hashlib.md5('password123'.encode()).hexdigest()
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', password_hash))
        conn.commit()
        conn.close()

init_db()

# Main page route
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'username' in session:
        return redirect(url_for('shop'))
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Insecure cryptographic storage: using MD5 hash
        password_hash = hashlib.md5(password.encode()).hexdigest()
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password_hash))
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect(url_for('shop'))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template_string('''
    <html>
    <head>
        <title>ShopEasy - Login</title>
    </head>
    <body>
        <h1>Welcome to ShopEasy</h1>
        <form method="post">
            <p><input type="text" name="username" placeholder="Username" required></p>
            <p><input type="password" name="password" placeholder="Password" required></p>
            <p><input type="submit" value="Login"></p>
        </form>
        {% if error %}
            <p style="color:red;">{{ error }}</p>
        {% endif %}
        <p>New user? <a href="/register">Register here</a></p>
    </body>
    </html>
    ''', error=error)

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        return redirect(url_for('shop'))
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Insecure cryptographic storage: using MD5 hash
        password_hash = hashlib.md5(password.encode()).hexdigest()
        try:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password_hash))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            error = 'Username already taken. Please choose another.'
    return render_template_string('''
    <html>
    <head>
        <title>ShopEasy - Register</title>
    </head>
    <body>
        <h1>Create a New Account</h1>
        <form method="post">
            <p><input type="text" name="username" placeholder="Username" required></p>
            <p><input type="password" name="password" placeholder="Password" required></p>
            <p><input type="submit" value="Register"></p>
        </form>
        {% if error %}
            <p style="color:red;">{{ error }}</p>
        {% endif %}
        <p>Already have an account? <a href="/">Login here</a></p>
    </body>
    </html>
    ''', error=error)

# Shop page route
@app.route('/shop')
def shop():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template_string('''
    <html>
    <head>
        <title>ShopEasy - Shop</title>
    </head>
    <body>
        <h1>Welcome, {{ session['username'] }}!</h1>
        <p>Explore our exclusive products below.</p>
        <!-- Add some dummy products -->
        <ul>
            <li>Product A - $10</li>
            <li>Product B - $20</li>
            <li>Product C - $30</li>
        </ul>
        <p><a href="/logout">Logout</a></p>
    </body>
    </html>
    ''')

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# Hidden Congratulations route
@app.route('/congratulations')
def congratulations():
    if 'congrats' in session and session['congrats'] == True:
        return render_template_string('''
        <html>
        <head>
            <title>Congratulations!</title>
        </head>
        <body>
            <h1>Congratulations!</h1>
            <p>You have successfully exploited the vulnerability.</p>
        </body>
        </html>
        ''')
    else:
        return redirect(url_for('shop'))

# Simulate insecure cryptographic storage vulnerability exploitation
@app.route('/exploit', methods=['GET', 'POST'])
def exploit():
    if request.method == 'POST':
        username = request.form.get('username')
        # An insecure way to dump user passwords
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username=?', (username,))
        result = c.fetchone()
        conn.close()
        if result:
            password_hash = result[0]
            # An attacker can reverse MD5 hashes if weak passwords are used
            if password_hash == hashlib.md5('password123'.encode()).hexdigest():
                session['congrats'] = True
                return redirect(url_for('congratulations'))
        return 'Exploit failed.'
    return 'Invalid request.'

if __name__ == '__main__':
    app.run(debug=True)