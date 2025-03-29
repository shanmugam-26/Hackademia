from flask import Flask, render_template_string, request, redirect, url_for, make_response

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
      <!-- Required meta tags and Bootstrap CSS -->
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Global Travel Agency</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <div class="container-fluid">
        <a class="navbar-brand" href="#">Global Travel Agency</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
          aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav">
            <li class="nav-item">
              <a class="nav-link active" aria-current="page" href="{{ url_for('home') }}">Home</a>
            </li>
            <li class="nav-item">
              <a class="nav-link" href="{{ url_for('login') }}">Login</a>
            </li>
          </ul>
        </div>
      </div>
    </nav>
    <div class="container">
      <h1 class="mt-5">Discover Your Next Adventure</h1>
      <p>Explore the world with our exclusive travel packages.</p>
    </div>
    </body>
    </html>
    """)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'user' and password == 'pass':
            resp = make_response(redirect(url_for('home')))
            resp.set_cookie('role', 'user')
            return resp
        elif username == 'admin' and password == 'admin':
            resp = make_response(redirect(url_for('admin')))
            resp.set_cookie('role', 'admin')
            return resp
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
      <!-- Required meta tags and Bootstrap CSS -->
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Login - Global Travel Agency</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
    <div class="container">
      <h1 class="mt-5">Login</h1>
      {% if error %}
      <div class="alert alert-danger" role="alert">
        {{ error }}
      </div>
      {% endif %}
      <form method="post">
        <div class="mb-3">
          <label for="username" class="form-label">Username</label>
          <input type="text" class="form-control" id="username" name="username" 
              placeholder="Enter username">
        </div>
        <div class="mb-3">
          <label for="password" class="form-label">Password</label>
          <input type="password" class="form-control" id="password" name="password" 
              placeholder="Password">
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
      </form>
    </div>
    </body>
    </html>
    """, error=error)

@app.route('/admin')
def admin():
    role = request.cookies.get('role')
    if role == 'admin':
        return render_template_string("""
        <!doctype html>
        <html lang="en">
        <head>
          <!-- Required meta tags and Bootstrap CSS -->
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Admin Panel - Global Travel Agency</title>
          <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
        <div class="container">
          <h1 class="mt-5">Admin Panel</h1>
          <p>Congratulations! You have accessed the admin panel.</p>
          <p>Your security skills are impressive.</p>
        </div>
        </body>
        </html>
        """)
    else:
        return redirect(url_for('login'))
)