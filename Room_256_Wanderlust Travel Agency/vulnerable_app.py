from flask import Flask, render_template_string, request, session, redirect, url_for
from flask_session import Session
import os

app = Flask(__name__)

# Secret key for session encryption
app.secret_key = 'replace_with_a_random_secret_key'

# Configure server-side sessions
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# HTML template using Bootstrap
html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Wanderlust Travel Agency</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="/">Wanderlust Travel Agency</a>
  <div class="collapse navbar-collapse">
    <ul class="navbar-nav mr-auto">
      {% if 'username' in session %}
      <li class="nav-item active">
        <a class="nav-link" href="#">Welcome, {{ session['username'] }}!</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="/logout">Logout</a>
      </li>
      {% else %}
      <li class="nav-item">
        <a class="nav-link" href="/login">Login</a>
      </li>
      {% endif %}
    </ul>
  </div>
</nav>
<div class="container">
    <h1 class="mt-5">Explore the World with Us!</h1>
    <p>Discover amazing destinations and book your dream vacation today.</p>
    {% if 'username' in session %}
    <div class="alert alert-success" role="alert">
      Logged in as {{ session['username'] }}.
    </div>
    {% endif %}
</div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - Wanderlust Travel Agency</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Login</h2>
    <form method="POST">
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" class="form-control" name="username" id="username" required>
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
    </form>
</div>
</body>
</html>
'''

congrats_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h1 class="mt-5">Congratulations!</h1>
    <p>You have successfully exploited the Session Fixation vulnerability.</p>
</div>
</body>
</html>
'''

valid_users = ['admin', 'user', 'guest']

@app.before_request
def fix_session():
    # Allow session fixation via 'session_id' GET parameter
    session_id = request.args.get('session_id')
    if session_id:
        session.sid = session_id

@app.route('/')
def index():
    return render_template_string(html_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        if username in valid_users:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid username", 401
    return render_template_string(login_template)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    if session.get('username') == 'admin':
        return render_template_string(congrats_template)
    else:
        return "Access Denied", 403

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)