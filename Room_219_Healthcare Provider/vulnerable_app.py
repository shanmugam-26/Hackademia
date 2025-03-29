from flask import Flask, render_template_string, request, redirect, url_for, session
from functools import wraps

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Simulated user database
users = {
    'user1': 'password1',
    'admin': 'adminpass'
}

# Simulated patient data
patient_data = {
    'user1': 'Patient records for user1...',
    'user2': 'Patient records for user2...',
    'admin': 'Confidential admin data...'
}

# Decorator for login required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Home page
@app.route('/')
def index():
    return render_template_string('''
    <!doctype html>
    <html lang="en">
      <head>
        <!-- Required meta tags -->
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>Healthcare Provider</title>
        <!-- Bootstrap CSS -->
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
      </head>
      <body>
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
          <a class="navbar-brand" href="#">Healthcare Provider</a>
          <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
              <li class="nav-item">
                <a class="nav-link" href="{{ url_for('index') }}">Home</a>
              </li>
              {% if 'username' in session %}
              <li class="nav-item">
                <a class="nav-link" href="{{ url_for('portal') }}">Portal</a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
              </li>
              {% else %}
              <li class="nav-item">
                <a class="nav-link" href="{{ url_for('login') }}">Login</a>
              </li>
              {% endif %}
            </ul>
          </div>
        </nav>
        <div class="container">
          <h1 class="mt-5">Welcome to Our Healthcare Provider</h1>
          <p class="lead">Providing top-notch healthcare services for over 50 years.</p>
          <p>Our patients are at the heart of everything we do. Log in to access your personalized patient portal.</p>
        </div>
        <!-- Optional JavaScript -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
            next_page = request.args.get('next')
            return redirect(next_page or url_for('portal'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template_string('''
    <!doctype html>
    <html lang="en">
      <head>
        <!-- Required meta tags -->
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>Login - Healthcare Provider</title>
        <!-- Bootstrap CSS -->
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
      </head>
      <body>
        <div class="container">
          <h1 class="mt-5">Login</h1>
          <form method="POST">
            <div class="mb-3">
              <label for="username" class="form-label">Username</label>
              <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="mb-3">
              <label for="password" class="form-label">Password</label>
              <input type="password" class="form-control" id="password" name="password" required>
            </div>
            {% if error %}
            <div class="mb-3 text-danger">
              {{ error }}
            </div>
            {% endif %}
            <button type="submit" class="btn btn-primary">Login</button>
          </form>
        </div>
        <!-- Optional JavaScript -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
      </body>
    </html>
    ''', error=error)

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# User portal
@app.route('/portal')
@login_required
def portal():
    username = session['username']
    data = patient_data.get(username, 'No data available.')
    return render_template_string('''
    <!doctype html>
    <html lang="en">
      <head>
        <!-- Meta tags and CSS -->
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>Portal - Healthcare Provider</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
      </head>
      <body>
        <div class="container">
          <h1 class="mt-5">Patient Portal</h1>
          <p>Welcome, {{ username }}!</p>
          <h3>Your Data:</h3>
          <p>{{ data }}</p>
          <a href="{{ url_for('logout') }}" class="btn btn-secondary">Logout</a>
        </div>
        <!-- JavaScript -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
      </body>
    </html>
    ''', username=username, data=data)

# Admin page with improper access control
@app.route('/admin')
def admin():
    # Improper access control vulnerability
    # Missing proper authentication check
    if 'username' in session and session['username'] == 'admin':
        # Admin is logged in
        pass  # Correctly authenticated
    # Due to flawed logic, unauthorized users can also access
    return render_template_string('''
    <!doctype html>
    <html lang="en">
      <head>
        <!-- Meta tags and CSS -->
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>Admin Panel - Healthcare Provider</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
      </head>
      <body>
        <div class="container">
          <h1 class="mt-5">Admin Panel</h1>
          <p>Welcome to the administrative control panel.</p>
          <p>Confidential data: All patient records, financial data, and private keys.</p>
          <p class="text-success">Congratulations! You have successfully exploited the improper access control vulnerability.</p>
          <a href="{{ url_for('logout') }}" class="btn btn-secondary">Logout</a>
        </div>
        <!-- JavaScript -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
      </body>
    </html>
    ''')
if __name__ == '__main__':
        app.run(debug=True)