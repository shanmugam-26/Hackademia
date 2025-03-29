from flask import Flask, request, redirect, url_for, render_template_string

app = Flask(__name__)

# Misconfigured admin_required decorator
def admin_required(f):
    def decorated_function(*args, **kwargs):
        # Intended to check for 'X-Admin-Auth' header
        # Misconfiguration: Checks for 'X-Admn-Auth' (misspelled)
        auth_header = request.headers.get('X-Admn-Auth')
        if auth_header != 'secretpassword':
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>National Agency of Cyber Security</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        /* Custom styles */
        body {
            padding-top: 56px;
        }
        .jumbotron {
            background-image: url('https://www.example.com/your-image.jpg');
            background-size: cover;
            color: white;
        }
    </style>
</head>
<body>

<!-- Navigation -->
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
  <a class="navbar-brand" href="#">NACS</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarResponsive" 
      aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>

  <div class="collapse navbar-collapse" id="navbarResponsive">
    <ul class="navbar-nav ml-auto">
      <li class="nav-item active">
        <a class="nav-link" href="/">Home
          <span class="sr-only">(current)</span>
        </a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="/news">News</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="/policies">Policies</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="/contact">Contact</a>
      </li>
    </ul>
  </div>
</nav>

<!-- Jumbotron Header -->
<header class="jumbotron my-4">
  <div class="container">
    <h1 class="display-3">National Agency of Cyber Security</h1>
    <p class="lead">Protecting our nation's cyberspace.</p>
    <a href="#" class="btn btn-primary btn-lg">Learn more</a>
  </div>
</header>

<!-- Content -->
<div class="container">
  <!-- Features Section -->
  <div class="row">
    <div class="col-lg-6">
      <h2>Our Mission</h2>
      <p>The National Agency of Cyber Security (NACS) is dedicated to safeguarding the nation's information infrastructure against cyber threats.</p>
      <ul>
        <li>Monitoring cyber threats</li>
        <li>Providing cybersecurity guidance</li>
        <li>Collaborating with international partners</li>
        <li>Enhancing public awareness</li>
      </ul>
      <p>Join us in our mission to secure the cyberspace.</p>
    </div>
    <div class="col-lg-6">
      <img class="img-fluid rounded" src="https://www.example.com/another-image.jpg" alt="">
    </div>
  </div>
  <!-- /.row -->
  
  <hr>
  
  <!-- Call to Action Section -->
  <div class="row mb-4">
    <div class="col-md-8">
      <p>Stay informed about the latest cybersecurity news and alerts.</p>
    </div>
    <div class="col-md-4">
      <a class="btn btn-lg btn-secondary btn-block" href="/subscribe">Subscribe Now</a>
    </div>
  </div>
</div>
<!-- /.container -->

<!-- Footer -->
<footer class="py-5 bg-dark">
  <div class="container">
    <p class="m-0 text-center text-white">© 2023 National Agency of Cyber Security</p>
  </div>
  <!-- /.container -->
</footer>

<!-- Bootstrap core JavaScript -->
<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"></script>

</body>
</html>
''')

@app.route('/admin')
@admin_required
def admin():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Panel - NACS</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>

<div class="container mt-5">
    <h1>Admin Panel</h1>
    <div class="alert alert-success" role="alert">
      Congratulations! You have accessed the admin panel.
    </div>
    <p>Secret content goes here...</p>
</div>

<!-- Bootstrap core JavaScript -->
<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"></script>

</body>
</html>
''')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)