from flask import Flask, render_template_string, request, redirect, url_for, session
from functools import wraps

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Simulated user database
users = {
    'user': 'password',
    'admin': 'adminpass'
}

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Home page
@app.route('/')
def home():
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>FitLife Fitness Center</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
            .header {background-color: #50b3a2; color: #fff; padding: 20px; text-align: center;}
            .nav {overflow: hidden; background-color: #333;}
            .nav a {float: left; display: block; color: #f2f2f2; text-align: center;
                    padding: 14px 16px; text-decoration: none;}
            .nav a:hover {background-color: #ddd; color: black;}
            .content {padding: 20px;}
            .footer {background-color: #50b3a2; color: #fff; padding: 10px; text-align: center;position:fixed;bottom:0;width:100%;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome to FitLife Fitness Center</h1>
        </div>
        <div class="nav">
            <a href="{{ url_for('home') }}">Home</a>
            <a href="{{ url_for('login') }}">Login</a>
            <a href="{{ url_for('classes') }}">Classes</a>
            <a href="{{ url_for('contact') }}">Contact Us</a>
        </div>
        <div class="content">
            <h2>Your journey to a healthier life starts here.</h2>
            <p>At FitLife, we provide top-notch fitness programs to help you achieve your goals.</p>
        </div>
        <div class="footer">
            <p>© 2023 FitLife Fitness Center</p>
        </div>
    </body>
    </html>
    ''')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>Login - FitLife Fitness Center</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
            .login-form {width: 300px; margin: 0 auto; padding-top: 100px;}
            input[type=text], input[type=password] {width: 100%; padding: 10px; margin: 5px 0;}
            input[type=submit] {background-color: #50b3a2; color: white; padding: 10px; width: 100%;}
            .error {color: red;}
        </style>
    </head>
    <body>
        <div class="login-form">
            <h2>Member Login</h2>
            <form method="post">
                <input type="text" name="username" placeholder="Username" required/><br/>
                <input type="password" name="password" placeholder="Password" required/><br/>
                <input type="submit" value="Login"/><br/>
                <span class="error">{{ error }}</span>
            </form>
        </div>
    </body>
    </html>
    ''', error=error)

# User dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>Dashboard - FitLife Fitness Center</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
            .content {padding: 20px;}
            .header {background-color: #50b3a2; color: #fff; padding: 20px; text-align: center;}
            .nav {overflow: hidden; background-color: #333;}
            .nav a {float: left; display: block; color: #f2f2f2; text-align: center;
                    padding: 14px 16px; text-decoration: none;}
            .nav a:hover {background-color: #ddd; color: black;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Your Dashboard</h1>
        </div>
        <div class="nav">
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('logout') }}">Logout</a>
            <a href="{{ url_for('classes') }}">Classes</a>
            <a href="{{ url_for('contact') }}">Contact Us</a>
        </div>
        <div class="content">
            <h2>Welcome, {{ session['username'] }}!</h2>
            <p>Here you can view your upcoming classes and membership details.</p>
        </div>
    </body>
    </html>
    ''')

# Classes page
@app.route('/classes')
def classes():
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>Classes - FitLife Fitness Center</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
            .content {padding: 20px;}
        </style>
    </head>
    <body>
        <div class="content">
            <h2>Our Classes</h2>
            <p>We offer a variety of classes to fit your fitness needs.</p>
        </div>
    </body>
    </html>
    ''')

# Contact page
@app.route('/contact')
def contact():
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>Contact Us - FitLife Fitness Center</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
            .content {padding: 20px;}
        </style>
    </head>
    <body>
        <div class="content">
            <h2>Contact Us</h2>
            <p>Feel free to reach out with any questions or concerns.</p>
        </div>
    </body>
    </html>
    ''')

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

# Admin page (Improper Access Control vulnerability)
@app.route('/admin')
def admin():
    # Improper Access Control: No authentication check for admin access
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>Admin Dashboard - FitLife Fitness Center</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #fff0f0;}
            .content {padding: 20px;}
            .header {background-color: #ff4d4d; color: #fff; padding: 20px; text-align: center;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Admin Dashboard</h1>
        </div>
        <div class="content">
            <h2>Congratulations!</h2>
            <p>You have successfully exploited the vulnerability and accessed the admin dashboard.</p>
        </div>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    app.run(debug=False)