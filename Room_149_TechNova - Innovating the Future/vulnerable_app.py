from flask import Flask, request, render_template_string, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'super secret key'

# Database setup
conn = sqlite3.connect('users.db', check_same_thread=False)
c = conn.cursor()
c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)')
# Add admin user
c.execute("SELECT * FROM users WHERE username='admin'")
if not c.fetchone():
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'adminpass')")
conn.commit()

# Templates
index_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TechNova - Innovating the Future</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f0f0; }
        .container { width: 600px; margin: 50px auto; background: #fff; padding: 20px; border-radius: 5px; }
        h1 { text-align: center; }
        form { display: flex; flex-direction: column; }
        input { margin-bottom: 10px; padding: 8px; font-size: 16px; }
        button { padding: 10px; font-size: 16px; background-color: #28a745; color: #fff; border: none; }
        .message { color: red; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #888; }
        .congrats { color: green; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to TechNova</h1>
        <p>At TechNova, we innovate the future with cutting-edge technology solutions.</p>
        {% if not session.get('logged_in') %}
        <h2>Login</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
            {% if message %}
            <p class="message">{{ message }}</p>
            {% endif %}
        </form>
        <p>Don't have an account? <a href="/register">Register here</a>.</p>
        {% else %}
        <h2>Dashboard</h2>
        <p>Welcome back, {{ session.get('username') }}!</p>
        {% if session.get('username') == 'admin' %}
        <p class="congrats">Congratulations! You have accessed the admin account.</p>
        <p><a href="{{ url_for('congratulations') }}">Go to your special page</a></p>
        {% else %}
        <p>Your future starts here.</p>
        {% endif %}
        <p><a href="/logout">Logout</a></p>
        {% endif %}
    </div>
    <div class="footer">
        &copy; 2023 TechNova Inc.
    </div>
</body>
</html>
'''

register_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Register - TechNova</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f0f0; }
        .container { width: 600px; margin: 50px auto; background: #fff; padding: 20px; border-radius: 5px; }
        h1 { text-align: center; }
        form { display: flex; flex-direction: column; }
        input { margin-bottom: 10px; padding: 8px; font-size: 16px; }
        button { padding: 10px; font-size: 16px; background-color: #007bff; color: #fff; border: none; }
        .message { color: red; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Create an Account</h1>
        <form method="POST" action="/register">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Register</button>
            {% if message %}
            <p class="message">{{ message }}</p>
            {% endif %}
        </form>
    </div>
    <div class="footer">
        &copy; 2023 TechNova Inc.
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
    <style>
        body { font-family: Arial, sans-serif; background-color: #dff0d8; }
        .container { width: 600px; margin: 50px auto; background: #fff; padding: 20px; border-radius: 5px; text-align: center; }
        h1 { color: #3c763d; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #888; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the Insecure Cryptographic Storage vulnerability!</p>
        <p>This challenge demonstrates the importance of secure coding practices.</p>
    </div>
    <div class="footer">
        &copy; 2023 TechNova Inc.
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    message = request.args.get('message')
    return render_template_string(index_template, message=message)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Insecure password storage and SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    c.execute(query)
    user = c.fetchone()
    if user:
        session['logged_in'] = True
        session['username'] = user[1]
        return redirect(url_for('index'))
    else:
        message = "Invalid credentials"
        return redirect(url_for('index', message=message))

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Insecure password storage and SQL Injection vulnerability
        query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
        c.execute(query)
        conn.commit()
        message = "Registration successful! You can now login."
    return render_template_string(register_template, message=message)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/congratulations')
def congratulations():
    if not session.get('logged_in') or session.get('username') != 'admin':
        return redirect(url_for('index'))
    return render_template_string(congrats_template)

if __name__ == '__main__':
    app.run(debug=True)