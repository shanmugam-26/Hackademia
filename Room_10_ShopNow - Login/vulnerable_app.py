from flask import Flask, render_template_string, request, redirect, url_for, session, make_response, flash
import hashlib
import random
import string

app = Flask(__name__)
app.secret_key = 'super-secret-key'

# Simulated database
users = {
    'alice': {
        'password': 'password1',
        'email': 'alice@example.com'
    },
    'bob': {
        'password': 'password2',
        'email': 'bob@example.com'
    },
    'admin': {
        'password': 'admin123',
        'email': 'admin@shopnow.com'
    }
}

reset_tokens = {}

# HTML templates
login_template = '''
<!doctype html>
<html>
<head>
<title>ShopNow - Login</title>
<style>
body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
h1 { color: #333; }
form { background-color: #fff; padding: 20px; margin: 50px auto; width: 300px; border-radius: 5px; }
label { display: block; margin-top: 10px; }
input[type="text"], input[type="password"], input[type="email"] { width: 100%; padding: 8px; }
input[type="submit"] { margin-top: 20px; padding: 10px; width: 100%; background-color: #4CAF50; color: #fff; border: none; }
a { text-decoration: none; color: #4CAF50; }
</style>
</head>
<body>
<h1>Welcome to ShopNow</h1>
<form action="/login" method="post">
    <label>Username:</label> <input type="text" name="username"/><br/>
    <label>Password:</label> <input type="password" name="password"/><br/>
    <input type="submit" value="Login"/>
</form>
<p><a href="/forgot">Forgot Password?</a></p>
</body>
</html>
'''

home_template = '''
<!doctype html>
<html>
<head>
<title>ShopNow - Home</title>
<style>
body { font-family: Arial, sans-serif; background-color: #fff; }
h1 { color: #333; }
p { font-size: 18px; }
a { text-decoration: none; color: #4CAF50; }
</style>
</head>
<body>
<h1>Welcome back, {{ username }}</h1>
<p>Exclusive deals await!</p>
<p><a href="/logout">Logout</a></p>
</body>
</html>
'''

forgot_template = '''
<!doctype html>
<html>
<head>
<title>ShopNow - Reset Password</title>
<style>
body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
h1 { color: #333; }
form { background-color: #fff; padding: 20px; margin: 50px auto; width: 300px; border-radius: 5px; }
label { display: block; margin-top: 10px; }
input[type="email"] { width: 100%; padding: 8px; }
input[type="submit"] { margin-top: 20px; padding: 10px; width: 100%; background-color: #4CAF50; color: #fff; border: none; }
</style>
</head>
<body>
<h1>Reset Password</h1>
<form action="/forgot" method="post">
    <label>Email:</label> <input type="email" name="email"/><br/>
    <input type="submit" value="Reset Password"/>
</form>
</body>
</html>
'''

reset_template = '''
<!doctype html>
<html>
<head>
<title>ShopNow - Set New Password</title>
<style>
body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
h1 { color: #333; }
form { background-color: #fff; padding: 20px; margin: 50px auto; width: 300px; border-radius: 5px; }
label { display: block; margin-top: 10px; }
input[type="password"] { width: 100%; padding: 8px; }
input[type="submit"] { margin-top: 20px; padding: 10px; width: 100%; background-color: #4CAF50; color: #fff; border: none; }
</style>
</head>
<body>
<h1>Set New Password</h1>
<form action="/reset" method="post">
    <input type="hidden" name="token" value="{{ token }}"/>
    <label>New Password:</label> <input type="password" name="password"/><br/>
    <input type="submit" value="Set Password"/>
</form>
</body>
</html>
'''

congrats_template = '''
<!doctype html>
<html>
<head>
<title>Congratulations!</title>
<style>
body { font-family: Arial, sans-serif; background-color: #fff; text-align: center; margin-top: 100px; }
h1 { color: #4CAF50; }
p { font-size: 18px; }
</style>
</head>
<body>
<h1>Congratulations!</h1>
<p>You have successfully exploited the Broken Authentication vulnerability!</p>
</body>
</html>
'''

@app.route('/')
def index():
    if 'username' in session:
        return render_template_string(home_template, username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Broken Authentication: Insecure password verification
        if username in users and users[username]['password'] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template_string(login_template)

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        # Vulnerability: Predictable reset tokens
        token = email.replace('@', '').replace('.', '')
        reset_tokens[token] = email
        flash('Password reset link has been sent to your email.')
        # Normally, we would send an email with the reset link
    return render_template_string(forgot_template)

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if request.method == 'GET':
        token = request.args.get('token')
        if token in reset_tokens:
            return render_template_string(reset_template, token=token)
        else:
            return 'Invalid token', 404
    elif request.method == 'POST':
        token = request.form['token']
        new_password = request.form['password']
        if token in reset_tokens:
            email = reset_tokens.pop(token)
            # Find the user by email
            for user, info in users.items():
                if info['email'] == email:
                    users[user]['password'] = new_password
                    flash('Password has been reset.')
                    if user == 'admin':
                        return redirect(url_for('congrats'))
                    return redirect(url_for('login'))
        else:
            return 'Invalid token', 404
    return 'Method not allowed', 405

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/congrats')
def congrats():
    return render_template_string(congrats_template)

if __name__ == '__main__':
    app.run(debug=True)