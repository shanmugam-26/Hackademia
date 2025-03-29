from flask import Flask, render_template_string, request, redirect, url_for, flash, session, abort
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Simulated user database
users = {
    'user': 'password',
    # Note: No 'admin' user is defined here
}

# Home route
@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
        return render_template_string(home_page_template, username=username)
    else:
        return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template_string(login_page_template)

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Admin route with improper access control
@app.route('/admin')
def admin():
    # Improper Access Control Vulnerability:
    # The admin page should be restricted to admin users only,
    # but due to missing access control, any authenticated user can access it.

    # Intended access control (commented out):
    # if 'username' not in session or session['username'] != 'admin':
    #     abort(403)

    return render_template_string(admin_page_template)

# 403 Forbidden error handler
@app.errorhandler(403)
def forbidden(error):
    return render_template_string(error_403_template), 403

# Templates
login_page_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Trust Bank - Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #f5f5f5; }
        .login-form { max-width: 400px; margin: auto; padding: 50px 0; }
    </style>
</head>
<body>
<div class="login-form">
    <div class="card">
        <div class="card-body">
            <h3 class="card-title text-center">Secure Trust Bank</h3>
            <h5 class="card-subtitle mb-4 text-center">Member Login</h5>
            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                {% for category, message in messages %}
                  <div class="alert alert-{{ category }}">{{ message }}</div>
                {% endfor %}
              {% endif %}
            {% endwith %}
            <form method="post">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" class="form-control" required autofocus>
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" class="form-control" required>
                </div>
                <button type="submit" class="btn btn-primary btn-block">Login</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>
'''

home_page_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Trust Bank - Dashboard</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        .navbar-custom { background-color: #004085; }
        .nav-link { color: #ffffff !important; }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-custom">
  <a class="navbar-brand text-white" href="#">Secure Trust Bank</a>
  <div class="collapse navbar-collapse">
    <ul class="navbar-nav ml-auto">
      <li class="nav-item">
        <span class="navbar-text text-white mr-3">Welcome, {{ username }}</span>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
      </li>
    </ul>
  </div>
</nav>
<div class="container mt-5">
    <h2>Account Dashboard</h2>
    <p>Your account balance: <strong>$12,345.67</strong></p>
    <p>Last login: <strong>Today at 9:00 AM</strong></p>
    <p><a href="{{ url_for('home') }}">Refresh</a> | <a href="{{ url_for('admin') }}">Admin Panel</a></p>
</div>
</body>
</html>
'''

admin_page_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Trust Bank - Admin Panel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #e9ecef; }
        .congrats-message { margin-top: 100px; }
    </style>
</head>
<body>
<div class="container text-center congrats-message">
    <h1>Congratulations!</h1>
    <p>You have successfully accessed the admin panel.</p>
    <p>This page should be restricted, but improper access controls allowed you to access it.</p>
</div>
</body>
</html>
'''

error_403_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>403 Forbidden</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #f8d7da; }
        .error-message { margin-top: 100px; }
    </style>
</head>
<body>
<div class="container text-center error-message">
    <h1>403 Forbidden</h1>
    <p>You do not have permission to access this resource.</p>
</div>
</body>
</html>
'''
if __name__ == '__main__':
    app.run(debug=True)