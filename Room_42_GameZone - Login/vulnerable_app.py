from flask import Flask, request, redirect, url_for, render_template_string, session
from werkzeug.security import check_password_hash, generate_password_hash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

users = {
    1: {'id': 1, 'username': 'player1', 'password': generate_password_hash('password1'), 'profile': 'Welcome to Player 1\'s profile! You have 1000 gold coins and 500 experience points.'},
    2: {'id': 2, 'username': 'player2', 'password': generate_password_hash('password2'), 'profile': 'Welcome to Player 2\'s profile! You have 1500 gold coins and 700 experience points.'},
    3: {'id': 3, 'username': 'player3', 'password': generate_password_hash('password3'), 'profile': 'Welcome to Player 3\'s profile! You have 2000 gold coins and 900 experience points.'},
    0: {'id': 0, 'username': 'admin', 'password': generate_password_hash('adminpass'), 'profile': 'Admin Secret Profile: You have accessed the administrative controls.'}
}

login_page = '''
<!doctype html>
<html lang="en">
<head>
    <title>GameZone - Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container" style="max-width: 500px; margin-top: 100px;">
    <h2 class="text-center">Welcome to GameZone</h2>
    <form method="post">
        {% if error %}
        <div class="alert alert-danger" role="alert">{{ error }}</div>
        {% endif %}
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" class="form-control" name="username" id="username" placeholder="Enter username" required>
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" class="form-control" name="password" id="password" placeholder="Enter password" required>
        </div>
        <button type="submit" class="btn btn-primary btn-block">Login</button>
    </form>
</div>
</body>
</html>
'''

dashboard_page = '''
<!doctype html>
<html lang="en">
<head>
    <title>GameZone - Dashboard</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">GameZone</a>
  <ul class="navbar-nav ml-auto">
    <li class="nav-item">
      <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
    </li>
  </ul>
</nav>
<div class="container" style="margin-top: 50px;">
    <h3>Dashboard</h3>
    <p>Welcome to your dashboard!</p>
    <a href="{{ url_for('profile', id=session['user_id']) }}" class="btn btn-primary">View Profile</a>
</div>
</body>
</html>
'''

profile_page = '''
<!doctype html>
<html lang="en">
<head>
    <title>GameZone - Profile</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">GameZone</a>
  <ul class="navbar-nav ml-auto">
    <li class="nav-item">
      <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
    </li>
  </ul>
</nav>
<div class="container" style="margin-top: 50px;">
    <h3>Profile</h3>
    <p>{{ profile|safe }}</p>
</div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        for user in users.values():
            if user['username'] == username and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                return redirect(url_for('dashboard'))
        return render_template_string(login_page, error='Invalid username or password')
    return render_template_string(login_page)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template_string(dashboard_page)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = request.args.get('id')
    if not user_id:
        user_id = session['user_id']
    else:
        user_id = int(user_id)
    user = users.get(user_id)
    if user:
        if user_id == 0:  # Admin profile
            return render_template_string(profile_page, profile=user['profile'] + '<br><br><strong>Congratulations! You have found the secret admin profile.</strong>')
        return render_template_string(profile_page, profile=user['profile'])
    else:
        return 'Profile not found', 404

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)