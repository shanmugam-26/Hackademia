from flask import Flask, render_template_string, request, redirect, url_for, session
from hashlib import sha256

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# In-memory "database" of users
users = {
    'user': sha256('password'.encode()).hexdigest()
}

# Templates
home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Delicious Bites Restaurant</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="/">Delicious Bites</a>
  <div class="collapse navbar-collapse">
    <ul class="navbar-nav ml-auto">
      {% if 'username' in session %}
      <li class="nav-item">
        <a class="nav-link" href="/dashboard">Dashboard</a>
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
    <h1 class="mt-5">Welcome to Delicious Bites!</h1>
    <p>Your favorite place for exquisite dining experiences.</p>
</div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - Delicious Bites</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Login to Your Account</h2>
    <form method="POST">
        <div class="form-group mt-3">
            <label>Username</label>
            <input type="text" name="username" class="form-control" required/>
        </div>
        <div class="form-group mt-3">
            <label>Password</label>
            <input type="password" name="password" class="form-control" required/>
        </div>
        <button type="submit" class="btn btn-primary mt-3">Login</button>
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
    <title>Dashboard - Delicious Bites</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="/">Delicious Bites</a>
  <div class="collapse navbar-collapse">
    <ul class="navbar-nav ml-auto">
      <li class="nav-item">
        <span class="nav-link">Welcome, {{ session['username'] }}</span>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="/logout">Logout</a>
      </li>
    </ul>
  </div>
</nav>
<div class="container">
    <h2 class="mt-5">User Dashboard</h2>
    <p>Explore our exclusive features and offers.</p>
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
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{
            background-color: #f8f9fa;
            text-align: center;
            padding-top: 50px;
        }}
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the Session Fixation vulnerability!</p>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = sha256(request.form['password'].encode()).hexdigest()
        if username in users and users[username] == password:
            session['username'] = username
            # Vulnerability: Session ID is not regenerated after login
            return redirect(url_for('dashboard'))
    return render_template_string(login_template)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        # Check for Session Fixation exploitation
        if session.get('fixation'):
            return render_template_string(congrats_template)
        return render_template_string(dashboard_template)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Route to simulate the vulnerability exploitation
@app.route('/set_session')
def set_session():
    session_key = request.args.get('key')
    if session_key:
        session['session_id'] = session_key
        session['fixation'] = True
    return redirect(url_for('home'))
if __name__ == '__main__':
        app.run(debug=True)