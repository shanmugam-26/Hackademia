from flask import Flask, render_template_string, request, session, redirect, url_for

app = Flask(__name__)
app.secret_key = 'supersecretkey'

home_template = '''
<!doctype html>
<html lang="en">
<head>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>HealthCare Provider - Home</title>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="/">HealthCare Provider</a>
  <div class="collapse navbar-collapse">
    <ul class="navbar-nav ml-auto">
      {% if 'username' in session %}
      <li class="nav-item">
        <a class="nav-link" href="/dashboard">Dashboard</a>
      </li>
      {% endif %}
      <li class="nav-item">
        {% if 'username' in session %}
        <a class="nav-link" href="/logout">Logout</a>
        {% else %}
        <a class="nav-link" href="/login">Login</a>
        {% endif %}
      </li>
    </ul>
  </div>
</nav>
<div class="container mt-5">
    <h1>Welcome to HealthCare Provider</h1>
    <p>Your health is our priority. We offer comprehensive healthcare services.</p>
    <p>Please <a href="/login">login</a> to access your dashboard.</p>
</div>
</body>
</html>
'''

login_template = '''
<!doctype html>
<html lang="en">
<head>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>HealthCare Provider - Login</title>
</head>
<body>
<div class="container mt-5">
    <h2>Login</h2>
    {% if error %}
    <div class="alert alert-danger" role="alert">
        {{ error }}
    </div>
    {% endif %}
    <form method="post">
        <div class="form-group mt-3">
            <label for="username">Username</label>
            <input type="text" class="form-control" name="username" id="username" placeholder="Enter username" required>
        </div>
        <div class="form-group mt-3">
            <label for="password">Password</label>
            <input type="password" class="form-control" name="password" id="password" placeholder="Password" required>
        </div>
        <button type="submit" class="btn btn-primary mt-3">Login</button>
    </form>
</div>
</body>
</html>
'''

dashboard_template = '''
<!doctype html>
<html lang="en">
<head>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>HealthCare Provider - Dashboard</title>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="/">HealthCare Provider</a>
  <div class="collapse navbar-collapse">
    <ul class="navbar-nav ml-auto">
      <li class="nav-item">
        {% if 'username' in session %}
        <a class="nav-link" href="/logout">Logout</a>
        {% else %}
        <a class="nav-link" href="/login">Login</a>
        {% endif %}
      </li>
    </ul>
  </div>
</nav>
<div class="container mt-5">
    <h2>Welcome, {{ username }}</h2>
    <p>This is your dashboard.</p>
    {% if username == 'admin' %}
    <div class="alert alert-success" role="alert">
        Congratulations! You've successfully exploited the authentication bypass vulnerability.
    </div>
    {% endif %}
</div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'adminpass':
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template_string(login_template, error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template_string(dashboard_template, username=session['username'])
    elif request.args.get('user'):
        # Authentication bypass vulnerability
        return render_template_string(dashboard_template, username=request.args.get('user'))
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))
if __name__ == '__main__':
        app.run(debug=True)