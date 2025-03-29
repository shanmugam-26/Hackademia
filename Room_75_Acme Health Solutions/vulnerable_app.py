from flask import Flask, render_template_string, request, redirect, url_for, make_response
app = Flask(__name__)

patients = [
    {
        "name": "John Doe",
        "dob": "1990-01-01",
        "medical_record": "Patient has hypertension."
    },
    {
        "name": "Jane Smith",
        "dob": "1985-06-15",
        "medical_record": "Patient is recovering from surgery."
    }
]

home_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Acme Health Solutions</title>
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
<header class="bg-primary text-white text-center p-4">
  <h1>Welcome to Acme Health Solutions</h1>
  <p>Your health is our priority.</p>
</header>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">Acme Health</a>
  <div class="collapse navbar-collapse">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item active">
        <a class="nav-link" href="{{ url_for('index') }}">Home</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="{{ url_for('login') }}">Patient Login</a>
      </li>
    </ul>
  </div>
</nav>
<div class="container mt-4">
  <h2>About Us</h2>
  <p>Acme Health Solutions provides top-notch healthcare services with a patient-centered approach.</p>
</div>
<!-- TODO: Remember to disable debug mode in /api/patients before going live -->
<footer class="bg-dark text-white text-center p-4">
  <p>&copy; 2023 Acme Health Solutions</p>
</footer>
</body>
</html>
'''

login_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Patient Login - Acme Health Solutions</title>
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
<header class="bg-primary text-white text-center p-4">
  <h1>Patient Portal Login</h1>
</header>
<div class="container mt-4">
  <form method="post" action="{{ url_for('login') }}">
    <div class="form-group">
      <label for="username">Email address</label>
      <input type="email" class="form-control" id="username" name="username" placeholder="Enter email">
    </div>
    <div class="form-group">
      <label for="password">Password</label>
      <input type="password" class="form-control" id="password" name="password" placeholder="Password">
    </div>
    <button type="submit" class="btn btn-primary">Login</button>
  </form>
</div>
<footer class="bg-dark text-white text-center p-4">
  <p>&copy; 2023 Acme Health Solutions</p>
</footer>
</body>
</html>
'''

dashboard_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Dashboard - Acme Health Solutions</title>
  <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
<header class="bg-primary text-white text-center p-4">
  <h1>Welcome, {{ username }}</h1>
</header>
<div class="container mt-4">
  <h2>Your Appointments</h2>
  <p>You have no upcoming appointments.</p>
</div>
<footer class="bg-dark text-white text-center p-4">
  <p>&copy; 2023 Acme Health Solutions</p>
</footer>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(home_page_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # process login
        username = request.form['username']
        password = request.form['password']
        # For simplicity, accept any username and password
        resp = make_response(redirect(url_for('dashboard')))
        resp.set_cookie('username', username)
        return resp
    return render_template_string(login_page_html)

@app.route('/dashboard')
def dashboard():
    username = request.cookies.get('username')
    if not username:
        return redirect(url_for('login'))
    return render_template_string(dashboard_html, username=username)

@app.route('/api/patients')
def api_patients():
    auth = request.headers.get('Authorization')
    debug = request.args.get('debug')
    if auth == 'Bearer supersecrettoken' or debug == 'true':
        data = {'patients': patients}
        if debug == 'true':
            data['message'] = 'Congratulations, you have found the sensitive data exposure vulnerability!'
        return data
    else:
        return {'error': 'Unauthorized'}, 401
if __name__ == '__main__':
        app.run(debug=True)