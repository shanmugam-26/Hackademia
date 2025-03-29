from flask import Flask, request, render_template_string
import os

# Create necessary directories and files
os.makedirs('static/files', exist_ok=True)

# Create a dummy file in 'static/files'
with open('static/files/readme.txt', 'w') as f:
    f.write('This is a sample readme file.')

# Create the secret file in 'static/secret.txt'
with open('static/secret.txt', 'w') as f:
    f.write('Congratulations! You have successfully exploited the Directory Traversal vulnerability!')

# Initialize Flask app
app = Flask(__name__)

# Home route
@app.route('/')
def home():
    return render_template_string('''
<!doctype html>
<html lang="en">
  <head>
    <title>GameHub - Your Online Gaming Platform</title>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body>
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <a class="navbar-brand" href="#">GameHub</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"         aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
  </nav>
  <div class="container mt-5">
    <div class="jumbotron text-center">
      <h1 class="display-4">Welcome to GameHub!</h1>
      <p class="lead">Your ultimate destination for online gaming. Join now and play with friends!</p>
      <hr class="my-4">
      <p>Sign up today and get exclusive in-game items.</p>
      <a class="btn btn-primary btn-lg" href="#" role="button">Sign Up</a>
    </div>
    <!-- Games Section -->
    <div class="row">
      <div class="col-md-4">
        <h2>Game One</h2>
        <p>Experience the thrill of Game One, an adventure like no other.</p>
        <p><a class="btn btn-secondary" href="#" role="button">Play Now »</a></p>
      </div>
      <div class="col-md-4">
        <h2>Game Two</h2>
        <p>Challenge your skills with Game Two's puzzling missions.</p>
        <p><a class="btn btn-secondary" href="#" role="button">Play Now »</a></p>
       </div>
      <div class="col-md-4">
        <h2>Game Three</h2>
        <p>Join epic battles in Game Three's multiplayer universe.</p>
        <p><a class="btn btn-secondary" href="#" role="button">Play Now »</a></p>
      </div>
    </div>
  </div>
  <!-- Footer -->
  <footer class="bg-dark text-white text-center p-3 mt-4">
    &copy; 2023 GameHub. All rights reserved.
  </footer>
  <!-- Optional JavaScript -->
  <!-- jQuery and Bootstrap Bundle (includes Popper) -->
  <script src="https://code.jquery.com/jquery-3.6.0.min.js" crossorigin="anonymous"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
''')

# Download route with Directory Traversal vulnerability
@app.route('/download')
def download():
    filename = request.args.get('file')
    if not filename:
        return "No file specified.", 400
    # Intentionally vulnerable code
    try:
        file_path = os.path.join('static/files', filename)
        with open(file_path, 'rb') as f:
            content = f.read()
        return content
    except Exception as e:
        return "File not found.", 404

if __name__ == '__main__':
  app.run(debug=True, host='0.0.0.0', port=5000)