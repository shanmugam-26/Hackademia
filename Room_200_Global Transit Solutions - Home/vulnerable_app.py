from flask import Flask, render_template_string, request, redirect, url_for, session
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey123'

index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Global Transit Solutions - Home</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <a class="navbar-brand" href="/">Global Transit Solutions</a>
  </nav>
  <div class="container mt-5">
    <h1 class="display-4">Seamless Transportation Services</h1>
    <p class="lead">Connecting you to the world with our state-of-the-art transit solutions.</p>
    <hr class="my-4">
    <p>Our platform offers cutting-edge technologies to ensure you reach your destination safely and efficiently.</p>
    <a class="btn btn-primary btn-lg" href="/login" role="button">Employee Login</a>
  </div>
</body>
</html>
'''

login_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Global Transit Solutions - Employee Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
  .login-form {
      width: 340px;
      margin: 50px auto;
  }
  .login-form form {
      margin-bottom: 15px;
      background: #f7f7f7;
      box-shadow: 0px 2px 2px rgba(0,0,0,0.3);
      padding: 30px;
  }
  </style>
</head>
<body>
  <div class="login-form">
    <form action="{{ url_for('login') }}" method="post">
        <h2 class="text-center">Employee Login</h2>
        {% if error %}
        <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <div class="form-group">
            <input type="text" class="form-control" placeholder="Username" required="required" name="username">
        </div>
        <div class="form-group">
            <input type="password" class="form-control" placeholder="Password" required="required" name="password">
        </div>
        <div class="form-group">
            <input type='submit' class="btn btn-primary btn-block" value="Log in">
        </div>
    </form>
  </div>
</body>
</html>
'''

dashboard_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Global Transit Solutions - Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
  <nav class="navbar navbar-dark bg-dark">
    <span class="navbar-brand mb-0 h1">Global Transit Solutions</span>
  </nav>
  <div class="container mt-5">
    <h1>Welcome, {{ username }}</h1>
    <p class="lead">This is the employee dashboard.</p>
    {% if username == 'admin' %}
      <div class="alert alert-success">
        Congratulations! You have accessed the admin panel.
      </div>
    {% endif %}
  </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(index_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Process login
        username = request.form.get('username')
        password = request.form.get('password')

        # Vulnerability: Unsafe use of eval
        try:
            if username == 'admin' and eval(password):
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid username or password'
        except:
            error = 'Invalid username or password'

    return render_template_string(login_html, error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template_string(dashboard_html, username=session['username'])
    else:
        return redirect(url_for('login'))
if __name__ == '__main__':
      app.run(debug=True, host='0.0.0.0', port=5000)