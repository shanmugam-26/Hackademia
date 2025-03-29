from flask import Flask, render_template_string, request, redirect, url_for, make_response

app = Flask(__name__)

users = {
    'john': 'password123',
    'admin': 'supersecret'
}

home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureLife Insurance</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
    
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">SecureLife Insurance</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-
controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>  
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav">
          <li class="nav-item active">
            <a class="nav-link" href="{{ url_for('home') }}">Home <span class="sr-only">(current)</span></a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('about') }}">About Us</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('login') }}">Login</a>
          </li>
        </ul>
      </div>
    </nav>
    <!-- Content -->
    <div class="container mt-5">
        <h1>Welcome to SecureLife Insurance</h1>
        <p>Your trusted partner for life insurance solutions.</p>
    </div>
</body>
</html>
'''

about_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>About Us - SecureLife Insurance</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
    
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">SecureLife Insurance</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-
controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>  
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav">
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('home') }}">Home</a>
          </li>
          <li class="nav-item active">
            <a class="nav-link" href="{{ url_for('about') }}">About Us <span class="sr-only">(current)</span></a
></li>
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('login') }}">Login</a>
          </li>
        </ul>
      </div>
    </nav>
    <!-- Content -->
    <div class="container mt-5">
        <h1>About SecureLife Insurance</h1>
        <p>At SecureLife, we provide comprehensive life insurance solutions tailored to your needs.</p>
        <p>Contact us at (555) 123-4567 or visit our office for more information.</p>
    </div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - SecureLife Insurance</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
    
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">SecureLife Insurance</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-
controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>  
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav">
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('home') }}">Home</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('about') }}">About Us</a>
          </li>
          <li class="nav-item active">
            <a class="nav-link" href="{{ url_for('login') }}">Login <span class="sr-only">(current)</span></a
></li>
        </ul>
      </div>
    </nav>
    <!-- Login Form -->
    <div class="container mt-5">
        <h1>Login</h1>
        {% if error %}
            <div class="alert alert-danger" role="alert">
              {{ error }}
            </div>
        {% endif %}
        <form method="post">
          <div class="form-group">
            <label for="username">Username</label>
            <input type="text" class="form-control" name="username" id="username" placeholder="Enter username"
>
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" class="form-control" name="password" id="password" placeholder="Password">
          </div>
          <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
</body>
</html>
'''

user_dashboard_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - SecureLife Insurance</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
    
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">SecureLife Insurance</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-
controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>  
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav">
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('home') }}">Home</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('about') }}">About Us</a>
          </li>
          <li class="nav-item active">
            <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard <span class="sr-only">(current)</span
></a></li>
        </ul>
      </div>
    </nav>
    <!-- User Dashboard -->
    <div class="container mt-5">
        <h1>Welcome, {{ username }}</h1>
        <p>Your account details are as follows:</p>
        <ul>
            <li>Policy Number: 123456789</li>
            <li>Coverage: $500,000</li>
            <li>Premium Due Date: 2024-01-01</li>
        </ul>
    </div>
</body>
</html>
'''

admin_dashboard_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard - SecureLife Insurance</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
    
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">SecureLife Insurance</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-
controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>  
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav">
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('home') }}">Home</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('about') }}">About Us</a>
          </li>
          <li class="nav-item active">
            <a class="nav-link" href="{{ url_for('dashboard') }}">Admin Dashboard <span class="sr-only">(current
)</span></a></li>
        </ul>
      </div>
    </nav>
    <!-- Admin Dashboard -->
    <div class="container mt-5">
        <h1>Welcome, {{ username }}</h1>
        <p>As an administrator, you have access to all user data.</p>
        <p><strong>Congratulations!</strong> You have successfully exploited the broken authentication vulnerability.</p>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/about')
def about():
    return render_template_string(about_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Handle login
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('username', username)
            return resp
        else:
            error = 'Invalid credentials'
    return render_template_string(login_template, error=error)

@app.route('/dashboard')
def dashboard():
    username = request.cookies.get('username')
    if not username:
        return redirect(url_for('login'))
    if username == 'admin':
        return render_template_string(admin_dashboard_template, username=username)
    return render_template_string(user_dashboard_template, username=username)
if __name__ == '__main__':
      app.run(debug=True)