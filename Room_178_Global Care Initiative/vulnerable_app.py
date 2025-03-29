from flask import Flask, render_template_string, request, redirect, url_for, abort

app = Flask(__name__)

# Security Misconfiguration: Debug mode is enabled in production
app.config['DEBUG'] = True

# Simulating a Nonprofit Organization website using a modern CSS framework
@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Care Initiative</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
            <div class="container-fluid">
                <a class="navbar-brand" href="/">Global Care Initiative</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
                    aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
            </div>
        </nav>
        <div class="container mt-5">
            <h1 class="display-4">Empowering Communities Worldwide</h1>
            <p class="lead">Our mission is to bring sustainable solutions to communities in need.</p>
            <a href="/programs" class="btn btn-primary btn-lg">Explore Our Programs</a>
        </div>
    </body>
    </html>
    ''')

@app.route('/programs')
def programs():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Our Programs - Global Care Initiative</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <h2>Our Programs</h2>
            <ul>
                <li>Clean Water Initiative</li>
                <li>Education for All</li>
                <li>Healthcare Access</li>
            </ul>
            <a href="/" class="btn btn-secondary">Back to Home</a>
        </div>
    </body>
    </html>
    ''')

@app.route('/contact')
def contact():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - Global Care Initiative</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <h2>Contact Us</h2>
            <p>Email: info@globalcare.org</p>
            <p>Phone: +1 (555) 123-4567</p>
            <a href="/" class="btn btn-secondary">Back to Home</a>
        </div>
    </body>
    </html>
    ''')

# Misconfigured access control: Admin panel accessible without proper authentication
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        # Authentication logic is intended here but missing due to misconfiguration
        username = request.form.get('username')
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel - Global Care Initiative</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="container mt-5">
                <h2>Admin Panel</h2>
                <p>Welcome, {{ username }}!</p>
                <p><a href="/admin/secret" class="btn btn-warning">Admin Secrets</a></p>
            </div>
        </body>
        </html>
        ''', username=username)
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login - Global Care Initiative</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <h2>Admin Login</h2>
            <form method="post">
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" class="form-control" name="username" placeholder="Enter username">
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" name="password" placeholder="Enter password">
                </div>
                <!-- Authentication is supposed to be here but is missing -->
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
        </div>
    </body>
    </html>
    ''')

# Exposed secret admin route due to misconfiguration
@app.route('/admin/secret')
def admin_secret():
    # This should be protected but is accessible due to misconfiguration
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Secrets - Global Care Initiative</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container mt-5">
            <h2>Admin Secrets</h2>
            <p>Top Secret Information: Project Phoenix launch date is October 21st.</p>
            <a href="/congratulations" class="btn btn-success">Claim your reward</a>
        </div>
    </body>
    </html>
    ''')

@app.route('/congratulations')
def congratulations():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Congratulations!</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background-color: #e9f7ef; }
            .center { text-align: center; margin-top: 50px; }
        </style>
    </head>
    <body>
        <div class="container center">
            <h1>Congratulations!</h1>
            <p>You have successfully exploited the security misconfiguration.</p>
        </div>
    </body>
    </html>
    ''')

# Exposed configuration route due to misconfiguration
@app.route('/debug/config')
def debug_config():
    # Misconfiguration: Exposing sensitive configuration details
    config_values = {key: str(value) for key, value in app.config.items()}
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Config Debug - Global Care Initiative</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background-color: #fdfefe; }
            .container { margin-top: 20px; }
            pre { background-color: #f0f3f4; padding: 15px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Application Configuration</h2>
            <pre>{{ config_values }}</pre>
        </div>
    </body>
    </html>
    ''', config_values=config_values)
if __name__ == '__main__':
        app.run(host='0.0.0.0', port=5000)