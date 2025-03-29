from flask import Flask, render_template_string, request, redirect, url_for, session
import base64
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

users = {
    'john': {'password': 'password123'},
    'jane': {'password': 'supersecure'},
    'admin': {'password': 'adminpass'},
}

home_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>FitZone Fitness Center</title>
    <style>
        /* Some basic styling */
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0; padding:0;}
        header {background-color: #50b3a2; color:white; padding: 20px;}
        nav ul {list-style-type: none; margin:0; padding:0;}
        nav ul li {display: inline; margin-right: 10px;}
        nav ul li a {color:white; text-decoration: none;}
        main {padding: 20px;}
        footer {background-color: #50b3a2; color:white; text-align:center; padding: 10px; position:fixed; bottom:0; width:100%;}
    </style>
</head>
<body>
    <header>
        <h1>Welcome to FitZone Fitness Center</h1>
        <nav>
            <ul>
                <li><a href="{{ url_for('home') }}">Home</a></li>
                {% if 'username' in session %}
                <li><a href="{{ url_for('account') }}">Account</a></li>
                <li><a href="{{ url_for('logout') }}">Logout</a></li>
                {% else %}
                <li><a href="{{ url_for('login') }}">Login</a></li>
                <li><a href="{{ url_for('reset_request') }}">Reset Password</a></li>
                {% endif %}
            </ul>
        </nav>
    </header>
    <main>
        <h2>Your Health, Our Priority</h2>
        <p>Join us to get in the best shape of your life!</p>
    </main>
    <footer>
        &copy; 2023 FitZone Fitness Center
    </footer>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login - FitZone Fitness Center</title>
    <style>
        /* Basic styling */
        body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
        .login-box {width: 300px; margin: auto; margin-top: 100px; background-color: white; padding: 20px; border-radius: 5px;}
        input[type="text"], input[type="password"] {width: 100%; padding: 10px; margin: 5px 0;}
        input[type="submit"] {background-color: #50b3a2; color: white; border: none; padding: 10px; width: 100%;}
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Member Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username"/><br/>
            <input type="password" name="password" placeholder="Password"/><br/>
            <input type="submit" value="Login"/>
        </form>
        {% if error %}
        <p style="color:red;">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
'''

account_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Account - FitZone Fitness Center</title>
    <style>
        /* Basic styling */
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0; padding:0;}
        header {background-color: #50b3a2; color:white; padding: 20px;}
        nav ul {list-style-type: none; margin:0; padding:0;}
        nav ul li {display: inline; margin-right: 10px;}
        nav ul li a {color:white; text-decoration: none;}
        main {padding: 20px;}
    </style>
</head>
<body>
    <header>
        <h1>Welcome, {{ username }}</h1>
        <nav>
            <ul>
                <li><a href="{{ url_for('home') }}">Home</a></li>
                <li><a href="{{ url_for('account') }}">Account</a></li>
                <li><a href="{{ url_for('logout') }}">Logout</a></li>
            </ul>
        </nav>
    </header>
    <main>
        <h2>Account Details</h2>
        <p>Username: {{ username }}</p>
        <p>Membership Status: Active</p>
    </main>
</body>
</html>
'''

reset_request_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Reset Password - FitZone Fitness Center</title>
    <style>
        /* Basic styling */
        body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
        .reset-box {width: 300px; margin: auto; margin-top: 100px; background-color: white; padding: 20px; border-radius: 5px;}
        input[type="text"] {width: 100%; padding: 10px; margin: 5px 0;}
        input[type="submit"] {background-color: #50b3a2; color: white; border: none; padding: 10px; width: 100%;}
    </style>
</head>
<body>
    <div class="reset-box">
        <h2>Password Reset</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username"/><br/>
            <input type="submit" value="Reset Password"/>
        </form>
        {% if message %}
        <p style="color:green;">{{ message }}</p>
        {% endif %}
    </div>
</body>
</html>
'''

reset_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Reset Password - FitZone Fitness Center</title>
    <style>
        /* Basic styling */
        body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
        .reset-box {width: 300px; margin: auto; margin-top: 100px; background-color: white; padding: 20px; border-radius: 5px;}
        input[type="password"] {width: 100%; padding: 10px; margin: 5px 0;}
        input[type="submit"] {background-color: #50b3a2; color: white; border: none; padding: 10px; width: 100%;}
    </style>
</head>
<body>
    <div class="reset-box">
        <h2>Set New Password</h2>
        <form method="POST">
            <input type="password" name="password" placeholder="New Password"/><br/>
            <input type="submit" value="Set Password"/>
        </form>
        {% if error %}
        <p style="color:red;">{{ error }}</p>
        {% endif %}
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('account'))
        else:
            error = 'Invalid Credentials'
    return render_template_string(login_template, error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/account')
def account():
    if 'username' in session:
        username = session['username']
        return render_template_string(account_template, username=username)
    else:
        return redirect(url_for('login'))

@app.route('/reset', methods=['GET', 'POST'])
def reset_request():
    message = None
    if request.method == 'POST':
        username = request.form['username']
        if username in users:
            # Generate reset token (vulnerable)
            token = base64.b64encode(username.encode()).decode()
            reset_link = url_for('reset_password', token=token, _external=True)
            # In a real app, we would send the reset link via email
            message = f'Reset link: {reset_link}'
        else:
            message = 'User not found'
    return render_template_string(reset_request_template, message=message)

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    error = None
    try:
        username = base64.b64decode(token.encode()).decode()
    except Exception as e:
        return 'Invalid token'

    if username not in users:
        return 'Invalid token'

    if request.method == 'POST':
        password = request.form['password']
        users[username]['password'] = password
        return 'Password reset successful! You have found the vulnerability. Congratulations!'

    return render_template_string(reset_template, error=error)

if __name__ == '__main__':
    app.run(debug=True)