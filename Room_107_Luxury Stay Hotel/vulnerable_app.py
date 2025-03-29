from flask import Flask, render_template_string, request, redirect, url_for, session
from functools import wraps

app = Flask(__name__)
app.secret_key = 's3cr3t'

users = {
    'admin': 'admin123',  # supposed to be the password
    'user': 'user123'
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login', next=request.url))
    return decorated_function

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            stored_password = users[username]
            # Broken authentication vulnerability
            # Anyone can log in as 'admin' without knowing the password
            if password == stored_password or username == 'admin':
                session['logged_in'] = True
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid password.'
        else:
            error = 'Invalid username.'

    return render_template_string(login_template, error=error)

@app.route('/dashboard')
@login_required
def dashboard():
    username = session.get('username', 'Guest')
    if username == 'admin':
        congrats = 'Congratulations! You have exploited the vulnerability.'
    else:
        congrats = None
    return render_template_string(dashboard_template, username=username, congrats=congrats)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Luxury Stay Hotel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
   <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="{{ url_for('home') }}">Luxury Stay Hotel</a>
      <div class="collapse navbar-collapse">
        <ul class="navbar-nav mr-auto">
          {% if 'logged_in' in session %}
            <li class="nav-item">
              <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a>
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
        <div class="jumbotron mt-5">
            <h1 class="display-4">Welcome to Luxury Stay Hotel</h1>
            <p class="lead">Experience the ultimate comfort and luxury during your stay with us.</p>
            <hr class="my-4">
            <p>Indulge in world-class amenities and impeccable service.</p>
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
    <title>Luxury Stay Hotel - Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="{{ url_for('home') }}">Luxury Stay Hotel</a>
    </nav>
   <div class="container">
        <h1 class="mt-5">Login to Your Account</h1>
        {% if error %}
            <div class="alert alert-danger" role="alert">
              {{ error }}
            </div>
        {% endif %}
        <form method="post" action="{{ url_for('login') }}">
          <div class="form-group">
            <label for="username">Username</label>
            <input type="text" class="form-control" id="username" name="username" required>
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" class="form-control" id="password" name="password" required>
          </div>
          <button type="submit" class="btn btn-primary">Login</button>
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
    <title>Luxury Stay Hotel - Dashboard</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
   <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="{{ url_for('home') }}">Luxury Stay Hotel</a>
      <div class="collapse navbar-collapse">
        <ul class="navbar-nav mr-auto">
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
          </li>
        </ul>
      </div>
    </nav>
   <div class="container">
        <h1 class="mt-5">Welcome, {{ username }}</h1>
        {% if congrats %}
            <div class="alert alert-success" role="alert">
              {{ congrats }}
            </div>
        {% endif %}
        <p class="lead">Here's your personalized dashboard.</p>
   </div>
</body>
</html>
'''
if __name__ == '__main__':
  app.run(debug=True, host='0.0.0.0', port=5000)