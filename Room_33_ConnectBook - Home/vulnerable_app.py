from flask import Flask, render_template_string, request, redirect, url_for, session, make_response
import random
import string

app = Flask(__name__)
app.secret_key = 'supersecretkey'

users_db = {}  # Simulated in-memory database

def generate_session_id(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
        return render_template_string(home_template, username=username)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Session Fixation Vulnerability: Accept session ID from URL parameter
        session_id = request.args.get('session_id')
        if session_id:
            session['session_id'] = session_id  # Set session ID from URL parameter
            resp = make_response(render_template_string(login_template))
            resp.set_cookie('session', session_id)
            return resp
        else:
            return render_template_string(login_template)
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users_db and users_db[username]['password'] == password:
            session['username'] = username
            # Vulnerability: Not generating new session ID after login
            return redirect(url_for('home'))
        else:
            error = 'Invalid username or password'
            return render_template_string(login_template, error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string(register_template)
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users_db:
            error = 'Username already exists'
            return render_template_string(register_template, error=error)
        else:
            users_db[username] = {'password': password}
            success = 'Registration successful! Please login.'
            return render_template_string(register_template, success=success)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/congratulations')
def congratulations():
    return "Congratulations! You have successfully exploited the Session Fixation vulnerability."

home_template = """
<!DOCTYPE html>
<html>
<head>
    <title>ConnectBook - Home</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f0f5; }
        .nav { background-color: #4CAF50; color: white; padding: 10px; }
        .nav a { color: white; margin-right: 15px; text-decoration: none; }
        .content { padding: 20px; }
        .post { background-color: white; padding: 10px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="nav">
        <span>ConnectBook</span>
        <a href="{{ url_for('logout') }}" style="float:right;">Logout</a>
    </div>
    <div class="content">
        <h2>Welcome, {{ username }}!</h2>
        <div class="post">
            <p>Your personalized news feed appears here.</p>
        </div>
    </div>
</body>
</html>
"""

login_template = """
<!DOCTYPE html>
<html>
<head>
    <title>ConnectBook - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f0f5; }
        .login-box { width: 300px; margin: 100px auto; background-color: white; padding: 20px; border: 1px solid #ccc; }
        .login-box h2 { margin-top: 0; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Login</h2>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post" action="{{ url_for('login') }}">
            <label for="username">Username:</label><br>
            <input type="text" name="username" id="username" required /><br><br>
            <label for="password">Password:</label><br>
            <input type="password" name="password" id="password" required /><br><br>
            <input type="submit" value="Login" />
        </form>
        <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
    </div>
</body>
</html>
"""

register_template = """
<!DOCTYPE html>
<html>
<head>
    <title>ConnectBook - Register</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f0f5; }
        .register-box { width: 300px; margin: 100px auto; background-color: white; padding: 20px; border: 1px solid #ccc; }
        .register-box h2 { margin-top: 0; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="register-box">
        <h2>Register</h2>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        {% if success %}
            <p class="success">{{ success }}</p>
        {% endif %}
        <form method="post" action="{{ url_for('register') }}">
            <label for="username">Username:</label><br>
            <input type="text" name="username" id="username" required /><br><br>
            <label for="password">Password:</label><br>
            <input type="password" name="password" id="password" required /><br><br>
            <input type="submit" value="Register" />
        </form>
        <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
    </div>
</body>
</html>
"""

# Simulated secret area that uses the session fixation
@app.route('/secret')
def secret():
    if 'session_id' in session and session['session_id'] == request.cookies.get('session'):
        # Congratulations, the user has exploited the session fixation vulnerability
        return redirect(url_for('congratulations'))
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)