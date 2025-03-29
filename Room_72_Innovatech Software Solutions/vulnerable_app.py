from flask import Flask, render_template_string, request, redirect, url_for, session
import hashlib
import re

app = Flask(__name__)
app.secret_key = 'super-secret-key'

homepage_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Innovatech Software Solutions</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #e9ecef; margin: 0; padding: 0;}
        .header {background-color: #343a40; color: #fff; padding: 20px; text-align: center;}
        .content {padding: 20px;}
        .login-form {background-color: #fff; padding: 20px; margin: 0 auto; width: 300px; border-radius: 5px;}
        .login-form input {width: 100%; padding: 10px; margin: 5px 0;}
        .login-form button {width: 100%; padding: 10px; margin-top: 10px;}
        .footer {background-color: #343a40; color: #fff; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}
        a {color: #007bff; text-decoration: none;}
    </style>
</head>
<body>
    <div class="header">
        <h1>Innovatech Software Solutions</h1>
    </div>
    <div class="content">
        <h2>Welcome to Innovatech</h2>
        <p>At Innovatech, we deliver cutting-edge software solutions for businesses worldwide.</p>
        <p><a href="/login">Employee Portal Login</a></p>
    </div>
    <div class="footer">
        &copy; 2023 Innovatech Software Solutions
    </div>
</body>
</html>
'''

login_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Employee Portal Login - Innovatech</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #e9ecef;}
        .login-form {background-color: #fff; padding: 20px; margin: 50px auto; width: 300px; border-radius: 5px;}
        .login-form input {width: 100%; padding: 10px; margin: 5px 0;}
        .login-form button {width: 100%; padding: 10px; margin-top: 10px;}
        a {text-decoration: none;}
    </style>
</head>
<body>
    <div class="login-form">
        <h2>Employee Portal Login</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required/><br/>
            <input type="password" name="password" placeholder="Password" required/><br/>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
'''

dashboard_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Employee Dashboard - Innovatech</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #e9ecef;}
        .dashboard {padding: 20px;}
    </style>
</head>
<body>
    <div class="dashboard">
        <h1>Employee Dashboard</h1>
        <p>Welcome, {{ username }}!</p>
        <p>You have successfully accessed the employee dashboard.</p>
        <p><strong>Congratulations!</strong> You have successfully exploited the authentication bypass vulnerability.</p>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return render_template_string(homepage_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(login_html)
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        # Simulated user database
        users = {
            'alice': '5f4dcc3b5aa765d61d8327deb882cf99',  # password
            'bob': '202cb962ac59075b964b07152d234b70',    # 123
            'admin': '21232f297a57a5a743894a0e4a801fc3'   # admin
        }
        # Vulnerable authentication logic
        # Intentionally flawed regex allows authentication bypass
        pattern = '^{}$'.format(users.get(username, ''))
        if re.match(pattern, hashlib.md5(password.encode()).hexdigest()):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            # Incorrect credentials
            error_message = '<p style="color:red;">Invalid credentials</p>'
            return render_template_string(login_html + error_message)

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'username' in session:
        return render_template_string(dashboard_html, username=session['username'])
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=Fals)