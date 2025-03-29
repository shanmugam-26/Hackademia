from flask import Flask, render_template_string, request, redirect, url_for, session
import base64
from functools import wraps

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for session handling

users = {}  # username: encrypted_password

def encrypt(text):
    key = 'secretkey'
    encrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))
    return base64.urlsafe_b64encode(encrypted.encode()).decode()

def decrypt(encrypted):
    key = 'secretkey'
    encrypted = base64.urlsafe_b64decode(encrypted.encode()).decode()
    decrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(encrypted))
    return decrypted

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

index_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>National Security Portal</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f9f9f9; }
        .header { background-color: #004080; color: white; padding: 20px; text-align: center; }
        .content { margin: 20px; }
        .footer { background-color: #004080; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
        a { color: #004080; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="header">
        <h1>National Security Portal</h1>
    </div>
    <div class="content">
        <p>Welcome to the National Security Portal. Please <a href="{{ url_for('login') }}">Login</a> or <a href="{{ url_for('register') }}">Register</a>.</p>
    </div>
    <div class="footer">
        &copy; 2023 National Security Agency
    </div>
</body>
</html>
'''

register_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Register - National Security Portal</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f9f9f9; }
        .header { background-color: #004080; color: white; padding: 20px; text-align: center; }
        .content { margin: 20px; }
        .footer { background-color: #004080; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
        .form-group { margin-bottom: 15px; }
        label { display: block; }
        input[type=text], input[type=password] { width: 100%; padding: 8px; }
        input[type=submit] { background-color: #004080; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        input[type=submit]:hover { background-color: #002850; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Register - National Security Portal</h1>
    </div>
    <div class="content">
        <form method="post">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <input type="submit" value="Register">
        </form>
    </div>
    <div class="footer">
        &copy; 2023 National Security Agency
    </div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login - National Security Portal</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f9f9f9; }
        .header { background-color: #004080; color: white; padding: 20px; text-align: center; }
        .content { margin: 20px; }
        .footer { background-color: #004080; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
        .form-group { margin-bottom: 15px; }
        label { display: block; }
        input[type=text], input[type=password] { width: 100%; padding: 8px; }
        input[type=submit] { background-color: #004080; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        input[type=submit]:hover { background-color: #002850; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Login - National Security Portal</h1>
    </div>
    <div class="content">
        <form method="post">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <input type="submit" value="Login">
        </form>
    </div>
    <div class="footer">
        &copy; 2023 National Security Agency
    </div>
</body>
</html>
'''

dashboard_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - National Security Portal</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f9f9f9; }
        .header { background-color: #004080; color: white; padding: 20px; text-align: center; position: relative; }
        .logout { position: absolute; right: 20px; top: 20px; }
        .logout a { color: white; text-decoration: none; }
        .logout a:hover { text-decoration: underline; }
        .content { margin: 20px; }
        .footer { background-color: #004080; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome, {{ username }}!</h1>
        <div class="logout"><a href="{{ url_for('logout') }}">Logout</a></div>
    </div>
    <div class="content">
        <p>This is your dashboard. The content is classified.</p>
        <!--
        User backup data:
        {% for user, enc_pw in users.items() %}
        Username: {{ user }} | Encrypted Password: {{ enc_pw }}
        {% endfor %}
        -->
    </div>
    <div class="footer">
        &copy; 2023 National Security Agency
    </div>
</body>
</html>
'''

admin_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - National Security Portal</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fff0f0; }
        .header { background-color: #800000; color: white; padding: 20px; text-align: center; }
        .content { margin: 20px; }
        .footer { background-color: #800000; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
        .message { font-size: 1.2em; color: #800000; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Admin Panel</h1>
    </div>
    <div class="content">
        <p class="message">Congratulations! You have successfully exploited the vulnerability.</p>
    </div>
    <div class="footer">
        &copy; 2023 National Security Agency
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(index_template)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return 'User already exists!'
        encrypted_password = encrypt(password)
        users[username] = encrypted_password
        return redirect(url_for('login'))
    return render_template_string(register_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        encrypted_password = users.get(username)
        if encrypted_password and decrypt(encrypted_password) == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid username or password'
    return render_template_string(login_template)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string(dashboard_template, username=session['username'], users=users)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    if session['username'] == 'admin':
        return render_template_string(admin_template)
    else:
        return 'Access Denied'

if __name__ == '__main__':
    app.run(debug=True)