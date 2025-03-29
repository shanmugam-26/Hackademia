from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'secret_key_for_session'

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

index_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>XYZ University Portal</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
        h1 { color: #333; }
        .container { width: 50%; margin: auto; padding: 20px; background-color: #fff; }
        a { text-decoration: none; color: #0066cc; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to XYZ University</h1>
        {% if 'username' in session %}
        <p>Hello, {{ session['username'] }}!</p>
        <p><a href="{{ url_for('logout') }}">Logout</a></p>
        {% else %}
        <p><a href="{{ url_for('login') }}">Login</a> | <a href="{{ url_for('register') }}">Register</a></p>
        {% endif %}
    </div>
</body>
</html>
'''

login_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>XYZ University Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #e0e0e0; }
        h1 { color: #333; }
        .container { width: 30%; margin: auto; padding: 20px; background-color: #fff; }
        input[type=text], input[type=password] { width: 100%; padding: 8px; margin: 5px 0; }
        input[type=submit] { padding: 8px 16px; }
        a { text-decoration: none; color: #0066cc; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login to XYZ University Portal</h1>
        <form method="post">
            <label>Username:</label><br/>
            <input type="text" name="username" required/><br/>
            <label>Password:</label><br/>
            <input type="password" name="password" required/><br/><br/>
            <input type="submit" value="Login"/>
        </form>
        <p><a href="{{ url_for('register') }}">Register</a></p>
    </div>
</body>
</html>
'''

register_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>XYZ University Registration</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #e0e0e0; }
        h1 { color: #333; }
        .container { width: 30%; margin: auto; padding: 20px; background-color: #fff; }
        input[type=text], input[type=password] { width: 100%; padding: 8px; margin: 5px 0; }
        input[type=submit] { padding: 8px 16px; }
        a { text-decoration: none; color: #0066cc; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Register for XYZ University Portal</h1>
        <form method="post">
            <label>Username:</label><br/>
            <input type="text" name="username" required/><br/>
            <label>Password:</label><br/>
            <input type="password" name="password" required/><br/><br/>
            <input type="submit" value="Register"/>
        </form>
        <p><a href="{{ url_for('login') }}">Login</a></p>
    </div>
</body>
</html>
'''

congrats_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Congratulations!</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #d4edda; }
        h1 { color: #155724; }
        .container { width: 50%; margin: auto; padding: 20px; background-color: #fff; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Congratulations!</h1>
        <p>You've successfully exploited the Insecure Cryptographic Storage vulnerability!</p>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(index_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        # Insecure password storage and retrieval
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid credentials. Please try again."
    return render_template_string(login_html)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        # Storing password in plaintext
        c.execute("INSERT INTO users(username, password) VALUES(?, ?)", (username, password))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))
    return render_template_string(register_html)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/download')
def download():
    # Insecure direct object reference allowing download of sensitive data
    return app.send_static_file('users.db')

@app.route('/congratulations')
def congratulations():
    return render_template_string(congrats_html)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)