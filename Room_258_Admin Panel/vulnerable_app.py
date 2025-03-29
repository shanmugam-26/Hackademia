from flask import Flask, render_template_string, send_from_directory, request, redirect, url_for
import os

app = Flask(__name__, static_folder='static')

# Using Bootstrap via CDN
bootstrap_cdn = "https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"

# Create config.txt with sensitive information
with open('config.txt', 'w') as f:
    f.write('AdminPassword=SuperSecretPassword\n')

# Read AdminPassword from config.txt
with open('config.txt', 'r') as f:
    admin_password_line = f.readline()
    admin_password = admin_password_line.strip().split('=')[1]

# Simulated secret admin page
@app.route('/admin')
def admin():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Admin Panel</title>
        <link rel="stylesheet" href="{}">
    </head>
    <body>
        <div class="container">
            <h1>Congratulations!</h1>
            <p>You've successfully exploited the vulnerability.</p>
        </div>
    </body>
    </html>
    '''.format(bootstrap_cdn)

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == admin_password:
            return redirect(url_for('admin'))
        else:
            error = 'Incorrect password'
    return render_template_string(login_page, error=error, bootstrap_cdn=bootstrap_cdn)

login_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Admin Login</title>
    <link rel="stylesheet" href="{{ bootstrap_cdn }}">
</head>
<body>
    <div class="container">
        <h2>Admin Login</h2>
        {% if error %}
            <div class="alert alert-danger" role="alert">
                {{ error }}
            </div>
        {% endif %}
        <form method="POST">
            <div class="form-group">
                <label for="password">Admin Password</label>
                <input type="password" class="form-control" id="password" name="password" placeholder="Enter admin password">
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
</body>
</html>
'''

# Main page
@app.route('/')
def index():
    page = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Elegance Boutique - Home</title>
        <link rel="stylesheet" href="{{ bootstrap_cdn }}">
        <style>
            body {
                background-color: #f8f9fa;
            }
            .hero {
                background-image: url('https://via.placeholder.com/1200x400');
                background-size: cover;
                background-position: center;
                height: 400px;
                position: relative;
            }
            .hero-text {
                position: absolute;
                bottom: 50px;
                left: 50px;
                color: white;
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
          <a class="navbar-brand" href="#">Elegance Boutique</a>
          <button class="navbar-toggler" type="button" data-toggle="collapse" 
          data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" 
          aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
          </button>
        </nav>
        <div class="hero">
            <div class="hero-text">
                <h1>Discover the New Collection</h1>
                <p>Experience the epitome of fashion elegance.</p>
            </div>
        </div>
        <div class="container mt-5">
            <h2>Our Latest Arrivals</h2>
            <div class="row">
                <div class="col-md-4">
                    <img src="https://via.placeholder.com/300x400" class="img-fluid" alt="Product 1">
                    <h4 class="mt-2">Product 1</h4>
                </div>
                <div class="col-md-4">
                    <img src="https://via.placeholder.com/300x400" class="img-fluid" alt="Product 2">
                    <h4 class="mt-2">Product 2</h4>
                </div>
                <div class="col-md-4">
                    <img src="https://via.placeholder.com/300x400" class="img-fluid" alt="Product 3">
                    <h4 class="mt-2">Product 3</h4>
                </div>
            </div>
        </div>
        <!-- TODO: Remove before deployment -->
        <!-- Note: Remember to secure the /config endpoint -->
    </body>
    </html>
    '''
    return render_template_string(page, bootstrap_cdn=bootstrap_cdn)

# Misconfigured route exposing sensitive file
@app.route('/config')
def config():
    # Simulating exposure of configuration file
    return send_from_directory(directory='.', path='config.txt')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)