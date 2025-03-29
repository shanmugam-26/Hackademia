from flask import Flask, request, render_template_string, redirect, url_for, session
from werkzeug.security import check_password_hash
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'ThisIsASecretKeyForSessionSigning'
app.permanent_session_lifetime = timedelta(minutes=5)

# Simulated user database with hashed passwords
users = {
    'admin': 'pbkdf2:sha256:150000$VtBBEvFu$4ae8e5a2b0e52dfb4c391eaca4c29e6e8d7d90a1b0956b1b0f8b7f0b8b5d7a84',  # Password: admin123
    'user': 'pbkdf2:sha256:150000$8DYNJKwt$3c2d0e3f5a2f1b6c4e5f4a6d7e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7g'   # Password: userpass
}

# HTML templates
home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Aid Foundation</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #f4f4f4; }
        .container { margin-top: 50px; }
        .header { text-align: center; margin-bottom: 40px; }
        .footer { text-align: center; margin-top: 40px; font-size: 12px; color: #777; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="header">Global Aid Foundation</h1>
        <p>Welcome to the Global Aid Foundation. We are committed to providing assistance to communities worldwide.</p>
        {% if 'username' in session %}
            <p>Hello, {{ session['username'] }}!</p>
            <a href="{{ url_for('logout') }}" class="btn btn-primary">Logout</a>
        {% else %}
            <a href="{{ url_for('login') }}" class="btn btn-primary">Login</a>
        {% endif %}
    </div>
    <div class="footer">
        &copy; 2023 Global Aid Foundation. All rights reserved.
    </div>
</body>
</html>
'''

login_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - Global Aid Foundation</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #f4f4f4; }
        .login-container { margin-top: 100px; max-width: 400px; }
        .header { text-align: center; margin-bottom: 30px; }
        .footer { text-align: center; margin-top: 40px; font-size: 12px; color: #777; }
    </style>
</head>
<body>
    <div class="container login-container">
        <h2 class="header">Member Login</h2>
        <form method="POST">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            {% if request.method == 'POST' and error %}
                <div class="alert alert-danger" role="alert">
                    {{ error }}
                </div>
            {% endif %}
            <button type="submit" class="btn btn-primary btn-block">Login</button>
        </form>
    </div>
    <div class="footer">
        &copy; 2023 Global Aid Foundation. All rights reserved.
    </div>
</body>
</html>
'''

admin_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard - Global Aid Foundation</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #fff; }
        .container { margin-top: 50px; }
        .header { text-align: center; margin-bottom: 40px; }
        .footer { text-align: center; margin-top: 40px; font-size: 12px; color: #777; }
        .congrats { background-color: #d4edda; padding: 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="header">Admin Dashboard</h1>
        <div class="congrats">
            <h3>Congratulations!</h3>
            <p>You have successfully accessed the admin dashboard.</p>
        </div>
        <a href="{{ url_for('logout') }}" class="btn btn-primary">Logout</a>
    </div>
    <div class="footer">
        &copy; 2023 Global Aid Foundation. All rights reserved.
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        # Intentional broken authentication vulnerability
        if username in users:
            session['username'] = username
            if username == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('home'))
        else:
            error = 'Invalid username'
    return render_template_string(login_page, error=error)

@app.route('/admin')
def admin():
    if 'username' in session and session['username'] == 'admin':
        return render_template_string(admin_page)
    else:
        return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))
if __name__ == '__main__':
        app.run(debug=True)