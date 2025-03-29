from flask import Flask, render_template_string, request, session, redirect, url_for

app = Flask(__name__)
app.secret_key = 'supersecretkey'

home_template = '''
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>XYZ Consulting Firm</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <div class="container-fluid">
        <a class="navbar-brand" href="{{ url_for('home') }}">XYZ Consulting Firm</a>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav ms-auto">
            {% if session.get('username') %}
            <li class="nav-item">
              <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a>
            </li>
            {% else %}
            <li class="nav-item">
              <a class="nav-link" href="{{ url_for('login') }}">Login</a>
            </li>
            {% endif %}
          </ul>
        </div>
      </div>
    </nav>
    <!-- Jumbotron -->
    <div class="jumbotron jumbotron-fluid bg-primary text-white text-center py-5">
      <div class="container">
        <h1 class="display-4">Welcome to XYZ Consulting Firm</h1>
        <p class="lead">We provide top-notch consulting services to help your business thrive.</p>
      </div>
    </div>
    <!-- Content -->
    <div class="container mt-5">
      <h2>Our Services</h2>
      <p>At XYZ Consulting Firm, we offer a wide range of services to meet your needs. Our team of experts is dedicated to providing solutions that drive success and innovation.</p>
    </div>
    <!-- Footer -->
    <footer class="bg-light text-center text-lg-start mt-5">
      <div class="text-center p-3">
        &copy; 2023 XYZ Consulting Firm
      </div>
    </footer>
  </body>
</html>
'''

login_template = '''
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Login - XYZ Consulting Firm</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body>
    <!-- Container -->
    <div class="container mt-5">
      <h1>Login</h1>
      <form method="post" action="{{ url_for('login') }}">
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input type="text" class="form-control" id="username" name="username" required>
        </div>
        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input type="password" class="form-control" id="password" name="password" required>
        </div>
        <!-- Hidden role field (improper practice) -->
        <input type="hidden" name="role" value="user">
        <button type="submit" class="btn btn-primary">Login</button>
      </form>
    </div>
  </body>
</html>
'''

dashboard_template = '''
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Dashboard - XYZ Consulting Firm</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body>
    <!-- Navbar -->
    <nav class="navbar navbar-light bg-light">
      <div class="container-fluid">
        <span class="navbar-text">
          Logged in as {{ username }}
        </span>
        <div>
          <a class="btn btn-outline-secondary" href="{{ url_for('home') }}">Home</a>
        </div>
      </div>
    </nav>
    <!-- Content -->
    <div class="container mt-5">
      <h1>Dashboard</h1>
      <p>Welcome, {{ username }}!</p>
      {% if session.get('role') == 'admin' %}
      <a href="{{ url_for('admin') }}" class="btn btn-danger">Admin Panel</a>
      {% endif %}
    </div>
  </body>
</html>
'''

admin_template = '''
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Admin Panel - XYZ Consulting Firm</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body>
    <!-- Navbar -->
    <nav class="navbar navbar-light bg-light">
      <div class="container-fluid">
        <span class="navbar-text">
          Admin Panel
        </span>
        <div>
          <a class="btn btn-outline-secondary" href="{{ url_for('dashboard') }}">Dashboard</a>
        </div>
      </div>
    </nav>
    <!-- Content -->
    <div class="container mt-5">
      <h1>Admin Panel</h1>
      <p>Congratulations! You have accessed the admin panel.</p>
    </div>
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
        password = request.form['password']
        # Improper Access Control: Trusting the 'role' field from the client
        role = request.form.get('role', 'user')
        session['username'] = username
        session['role'] = role
        return redirect(url_for('dashboard'))
    else:
        return render_template_string(login_template)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template_string(dashboard_template, username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'username' in session and session.get('role') == 'admin':
        return render_template_string(admin_template)
    else:
        return redirect(url_for('login'))
if __name__ == '__main__':
          app.run(debug=True)