from flask import Flask, render_template_string, request, redirect, url_for, session
import hashlib
app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Simulated database using a dictionary
users_db = {}

# HTML templates
home_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>National Agency of Data Management</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f4f7; }
        .container { width: 60%; margin: auto; padding: 50px; }
        h1 { text-align: center; }
        nav { text-align: center; margin-bottom: 30px; }
        nav a { margin: 0 15px; text-decoration: none; color: #0366d6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to the National Agency of Data Management</h1>
        <nav>
            <a href="{{ url_for('home') }}">Home</a>
            {% if 'username' in session %}
                <a href="{{ url_for('dashboard') }}">Dashboard</a>
                <a href="{{ url_for('logout') }}">Logout</a>
            {% else %}
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('register') }}">Register</a>
            {% endif %}
        </nav>
        <p>The National Agency of Data Management is committed to protecting citizen data and ensuring secure access to resources.</p>
    </div>
</body>
</html>
'''

login_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>NADM - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f4f7; }
        .login-container { width: 300px; margin: auto; padding-top: 100px; }
        input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 5px 0; }
        button { width: 100%; padding: 10px; background-color: #0366d6; color: white; border: none; }
        a { display: block; text-align: center; margin-top: 10px; color: #0366d6; text-decoration: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Login to NADM</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required/><br/>
            <input type="password" name="password" placeholder="Password" required/><br/>
            <button type="submit">Login</button>
        </form>
        <a href="{{ url_for('register') }}">Register</a>
    </div>
</body>
</html>
'''

register_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>NADM - Register</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f4f7; }
        .register-container { width: 300px; margin: auto; padding-top: 100px; }
        input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 5px 0; }
        button { width: 100%; padding: 10px; background-color: #28a745; color: white; border: none; }
        a { display: block; text-align: center; margin-top: 10px; color: #0366d6; text-decoration: none; }
    </style>
</head>
<body>
    <div class="register-container">
        <h2>Register for NADM Access</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required/><br/>
            <input type="password" name="password" placeholder="Password" required/><br/>
            <button type="submit">Register</button>
        </form>
        <a href="{{ url_for('login') }}">Login</a>
    </div>
</body>
</html>
'''

dashboard_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>NADM - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f4f7; }
        .dashboard { width: 60%; margin: auto; padding: 50px; }
        h2 { text-align: center; }
        p { text-align: center; }
    </style>
</head>
<body>
    <div class="dashboard">
        <h2>Welcome, {{ username }}</h2>
        <p>You have access to confidential data management resources.</p>
    </div>
</body>
</html>
'''

congratulations_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Congratulations</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #e6ffe6; }
        .congrats { width: 60%; margin: auto; padding: 50px; text-align: center; }
        h2 { color: #28a745; }
    </style>
</head>
<body>
    <div class="congrats">
        <h2>Congratulations!</h2>
        <p>You have successfully exploited the vulnerability.</p>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users_db:
            # Insecure password check (using MD5)
            hashed_password = hashlib.md5(password.encode()).hexdigest()
            if users_db[username] == hashed_password:
                session['username'] = username
                return redirect(url_for('dashboard'))
        return render_template_string(login_page)
    else:
        return render_template_string(login_page)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Insecure password storage (using MD5)
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        users_db[username] = hashed_password
        return redirect(url_for('login'))
    else:
        return render_template_string(register_page)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template_string(dashboard_page, username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/admin')
def admin():
    # Hidden admin page to display the congratulations message
    if 'username' in session and session['username'] == 'admin':
        return render_template_string(congratulations_page)
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)