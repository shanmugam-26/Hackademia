from flask import Flask, render_template_string, request, redirect

app = Flask(__name__)

# Homepage template
homepage_html = """
<!doctype html>
<html lang="en">
  <head>
    <title>Acme Software Solutions</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- Bootstrap CSS via CDN -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
  </head>
  <body>
    <!-- Navigation Bar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
      <a class="navbar-brand" href="/">Acme Software Solutions</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" 
              aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
    </nav>
    <!-- Main Content -->
    <div class="container mt-5">
      <h1 class="display-4">Innovative Solutions for Modern Businesses</h1>
      <p class="lead">We deliver high-quality software tailored to your business needs.</p>
      <a href="/login" class="btn btn-success btn-lg">Client Login</a>
    </div>
    <!-- Footer -->
    <footer class="footer bg-light p-3 text-center mt-5">
      <span>&copy; 2023 Acme Software Solutions. All rights reserved.</span>
    </footer>
    <!-- Optional JavaScript -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.0/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# Login page template
login_html = """
<!doctype html>
<html lang="en">
  <head>
    <title>Client Login - Acme Software Solutions</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
  </head>
  <body>
    <!-- Navigation Bar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
      <a class="navbar-brand" href="/">Acme Software Solutions</a>
    </nav>
    <!-- Login Form -->
    <div class="container mt-5">
      <h2>Please sign in</h2>
      <form action="/auth" method="post">
        <input type="hidden" name="next" value="{{ next }}">
        <div class="form-group">
          <label for="username">Email address</label>
          <input type="email" class="form-control" name="username" id="username" placeholder="Enter email">
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" class="form-control" name="password" id="password" placeholder="Password">
        </div>
        <button type="submit" class="btn btn-primary">Sign in</button>
      </form>
    </div>
    <!-- Footer -->
    <footer class="footer bg-light p-3 text-center mt-5">
      <span>&copy; 2023 Acme Software Solutions. All rights reserved.</span>
    </footer>
    <!-- Optional JavaScript -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.0/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# Dashboard page template
dashboard_html = """
<!doctype html>
<html lang="en">
  <head>
    <title>Dashboard - Acme Software Solutions</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
  </head>
  <body>
    <!-- Navigation Bar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
      <a class="navbar-brand" href="/">Acme Software Solutions</a>
    </nav>
    <!-- Main Content -->
    <div class="container mt-5">
      <h2>Welcome to your dashboard</h2>
      <p>Here you can manage your projects and view analytics.</p>
    </div>
    <!-- Footer -->
    <footer class="footer bg-light p-3 text-center mt-5">
      <span>&copy; 2023 Acme Software Solutions. All rights reserved.</span>
    </footer>
    <!-- Optional JavaScript -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.0/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

# Congratulations page template
congrats_html = """
<!doctype html>
<html lang="en">
  <head>
    <title>Congratulations!</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
  </head>
  <body>
    <!-- Main Content -->
    <div class="container mt-5">
      <div class="alert alert-success" role="alert">
        <h4 class="alert-heading">Congratulations!</h4>
        <p>You have successfully exploited the unvalidated redirect vulnerability.</p>
        <hr>
        <p class="mb-0">Great work testing your security skills!</p>
      </div>
    </div>
    <!-- Optional JavaScript -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.0/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(homepage_html)

@app.route('/login')
def login():
    next_page = request.args.get('next', '/dashboard')
    return render_template_string(login_html, next=next_page)

@app.route('/auth', methods=['POST'])
def auth():
    username = request.form.get('username')
    password = request.form.get('password')
    next_url = request.form.get('next', '/dashboard')
    # Authentication logic would go here (omitted for brevity)
    # Unvalidated Redirect occurs here
    return redirect(next_url)

@app.route('/dashboard')
def dashboard():
    return render_template_string(dashboard_html)

@app.route('/congratulations')
def congratulations():
    return render_template_string(congrats_html)
if __name__ == '__main__':
        app.run(debug=True)