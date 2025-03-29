from flask import Flask, render_template_string, request, redirect, url_for, session
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Simulated user database
users = {
    'john_doe': {'password': '81dc9bdb52d04dc20036dbd8313ed055', 'balance': 1500.00},  # Password: 1234
    'jane_smith': {'password': 'c33367701511b4f6020ec61ded352059', 'balance': 3000.50}  # Password: 5678
}

# Templates with modern CSS framework (Bootstrap)
login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Bank - Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container mt-5">
    <h2 class="text-center">Secure Bank Login</h2>
    <form method="POST" action="/login">
        <div class="form-group">
            <label for="username">Account Username</label>
            <input type="text" class="form-control" id="username" name="username" placeholder="Enter your account username">
        </div>
        <div class="form-group">
            <label for="password">Account Password</label>
            <input type="password" class="form-control" id="password" name="password" placeholder="Enter your account password">
        </div>
        {% if error %}
            <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <button type="submit" class="btn btn-primary btn-block">Login</button>
    </form>
</div>
</body>
</html>
'''

account_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Bank - Account Overview</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container mt-5">
    <h2>Welcome, {{ username }}!</h2>
    <p>Your current account balance is:</p>
    <h3>${{ balance }}</h3>
    <a href="/logout" class="btn btn-secondary">Logout</a>
</div>
</body>
</html>
'''

admin_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Bank - Admin Panel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container mt-5">
    <h2>Admin Panel Accessed</h2>
    <p>Congratulations! You have successfully accessed the admin panel.</p>
    <p>This area contains sensitive administrative functions.</p>
    <a href="/logout" class="btn btn-secondary">Logout</a>
</div>
</body>
</html>
'''

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        user = users.get(username)
        if user and user['password'] == hashed_password:
            session['username'] = username
            return redirect(url_for('account'))
        else:
            error = 'Invalid username or password.'
    return render_template_string(login_template, error=error)

@app.route('/account')
def account():
    username = session.get('username')
    if username:
        user = users.get(username)
        return render_template_string(account_template, username=username, balance=user['balance'])
    else:
        return redirect(url_for('login'))

@app.route('/admin')
def admin():
    # Improper Access Control Vulnerability
    # Access to admin panel is improperly controlled
    username = session.get('username')
    if username:
        # Vulnerability: No proper check to ensure user is admin
        return render_template_string(admin_template)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
if __name__ == '__main__':
        app.run(debug=True)