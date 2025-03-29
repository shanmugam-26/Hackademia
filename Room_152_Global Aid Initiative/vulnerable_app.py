from flask import Flask, render_template_string, request, redirect, url_for, session, send_from_directory
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Global Aid Initiative</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
        header { background-color: #5dade2; color: white; padding: 20px; text-align: center; }
        nav { background-color: #333; overflow: hidden; }
        nav a { float: left; display: block; color: white; text-align: center;
                padding: 14px 16px; text-decoration: none; }
        nav a:hover { background-color: #ddd; color: black; }
        section { padding: 20px; }
        footer { background-color: #5dade2; color: white; text-align: center; padding: 10px; }
        .form-container { background-color: white; padding: 20px; margin: auto;
                          width: 50%; border: 1px solid #ccc; }
        .form-container input[type=text], .form-container input[type=password] {
            width: 100%; padding: 12px 20px; margin: 8px 0;
            display: inline-block; border: 1px solid #ccc; box-sizing: border-box;
        }
        .form-container button {
            background-color: #5dade2; color: white; padding: 14px 20px;
            margin: 8px 0; border: none; cursor: pointer; width: 100%;
        }
        .form-container button:hover {
            opacity: 0.8;
        }
    </style>
</head>
<body>
    <header>
        <h1>Global Aid Initiative</h1>
        <p>Making the world a better place, one step at a time.</p>
    </header>
    <nav>
        <a href="{{ url_for('home') }}">Home</a>
        <a href="{{ url_for('about') }}">About Us</a>
        <a href="{{ url_for('donate') }}">Donate</a>
        <a href="{{ url_for('login') }}" style="float:right;">Login</a>
        <a href="{{ url_for('register') }}" style="float:right;">Register</a>
    </nav>
    <section>
        <h2>Welcome to Global Aid Initiative</h2>
        <p>We are dedicated to providing aid to communities around the globe. Join us in our mission to make a positive impact on the world.</p>
    </section>
    <footer>
        <p>&copy; 2023 Global Aid Initiative. All rights reserved.</p>
    </footer>
</body>
</html>
''')

@app.route('/about')
def about():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>About Us - Global Aid Initiative</title>
</head>
<body>
    <h1>About Us</h1>
    <p>Global Aid Initiative is a nonprofit organization committed to delivering essential resources to communities in need.</p>
    <a href="{{ url_for('home') }}">Back to Home</a>
</body>
</html>
''')

@app.route('/donate')
def donate():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Donate - Global Aid Initiative</title>
</head>
<body>
    <h1>Donate</h1>
    <p>Your contributions make a real difference.</p>
    <a href="{{ url_for('home') }}">Back to Home</a>
</body>
</html>
''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Insecurely storing the password in plaintext
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists!"
        finally:
            conn.close()
        return redirect(url_for('login'))
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Register - Global Aid Initiative</title>
</head>
<body>
    <div class="form-container">
        <h1>Register</h1>
        <form method="post">
            <label for="username"><b>Username</b></label>
            <input type="text" name="username" required>

            <label for="password"><b>Password</b></label>
            <input type="password" name="password" required>

            <button type="submit">Register</button>
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

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials!"
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Login - Global Aid Initiative</title>
</head>
<body>
    <div class="form-container">
        <h1>Login</h1>
        <form method="post">
            <label for="username"><b>Username</b></label>
            <input type="text" name="username" required>

            <label for="password"><b>Password</b></label>
            <input type="password" name="password" required>

            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
''')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        if session['username'] == 'admin':
            return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Global Aid Initiative</title>
</head>
<body>
    <h1>Welcome, {{ session['username'] }}!</h1>
    <p>Congratulations! You have successfully exploited the vulnerability!</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
''')
        else:
            return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Global Aid Initiative</title>
</head>
<body>
    <h1>Welcome, {{ session['username'] }}!</h1>
    <p>This is your dashboard.</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
''')
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

# Simulate an unintended backup file exposure
@app.route('/backup/users.bak')
def backup():
    # Insecurely expose the user database backup
    return send_from_directory(directory='.', filename='users.db', as_attachment=True)

if __name__ == '__main__':
    # Create an admin user with a known password
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username=?', ('admin',))
    if not c.fetchone():
        # Store admin password insecurely
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', 'admin123'))
        conn.commit()
    conn.close()
    app.run(debug=True)