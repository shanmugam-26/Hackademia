from flask import Flask, render_template_string, request, redirect, url_for, make_response
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

SECRET_KEY = 'mysecret'  # Weak secret key for JWT

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('auth_token')
        if not token:
            return redirect(url_for('login'))
        try:
            # Decode JWT without verifying the signature (vulnerability)
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'], options={"verify_signature": False})
        except:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']  # 'student' or 'teacher'
        # Generate JWT token
        token = jwt.encode({
            'username': username,
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, SECRET_KEY)
        resp = make_response(redirect(url_for('dashboard')))
        resp.set_cookie('auth_token', token)
        return resp
    else:
        return render_template_string(login_template)

@app.route('/dashboard')
@login_required
def dashboard():
    token = request.cookies.get('auth_token')
    data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'], options={"verify_signature": False})
    username = data['username']
    role = data['role']
    return render_template_string(dashboard_template, username=username, role=role)

@app.route('/admin')
@login_required
def admin():
    token = request.cookies.get('auth_token')
    data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'], options={"verify_signature": False})
    role = data.get('role', '')
    if role == 'admin' or 'administrator':
        return render_template_string(admin_template)
    else:
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('auth_token', '', expires=0)
    return resp

home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>XYZ Educational Institution</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <div class="jumbotron mt-5">
        <h1>Welcome to XYZ Educational Institution</h1>
        <p>Your future begins here.</p>
        <a class="btn btn-primary btn-lg" href="{{ url_for('login') }}" role="button">Login</a>
    </div>
</div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - XYZ Educational Institution</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Login to Your Account</h2>
    <form method="post" action="{{ url_for('login') }}">
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" class="form-control" required>
        </div>
        <div class="form-group">
            <label for="role">I am a:</label>
            <select id="role" name="role" class="form-control">
                <option value="student">Student</option>
                <option value="teacher">Teacher</option>
            </select>
        </div>
        <button type="submit" class="btn btn-success">Login</button>
    </form>
</div>
</body>
</html>
'''

dashboard_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - XYZ Educational Institution</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Dashboard</h2>
    <p>Welcome, {{ username }}!</p>
    <p>You are logged in as <strong>{{ role }}</strong>.</p>
    <a href="{{ url_for('admin') }}">Go to Admin Panel</a><br>
    <a href="{{ url_for('logout') }}">Logout</a>
</div>
</body>
</html>
'''

admin_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Panel - XYZ Educational Institution</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #fffbf0;
        }
    </style>
</head>
<body>
<div class="container">
    <h2 class="mt-5">Admin Panel</h2>
    <p>Congratulations! You have accessed the admin panel.</p>
    <p>This area is restricted to administrators only.</p>
</div>
</body>
</html>
'''
if __name__ == '__main__':
        app.run(debug=True)