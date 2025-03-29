from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

SECRET_KEY = 's3cr3t_k3y_1234567890'

@app.route('/', methods=['GET', 'POST'])
def index():
    # Define the HTML template
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Elite Bank - Secure Online Banking</title>
        <!-- Bootstrap CSS -->
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
        <!-- Custom CSS -->
        <style>
            body {
                background-color: #f5f5f5;
            }
            .navbar {
                margin-bottom: 20px;
            }
            .login-form {
                width: 400px;
                margin: 0 auto;
                padding: 30px 0;
            }
            .login-form form {
                background: #fff;
                padding: 40px;
                border: 1px solid #f3f3f3;
                box-shadow: 0 0 8px rgba(0,0,0,.1);
            }
            .login-form h2 {
                margin: 0 0 15px;
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
            <a class="navbar-brand" href="/">Elite Bank</a>
            <div class="collapse navbar-collapse">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item"><a class="nav-link" href="/">Home</a></li>
                    <li class="nav-item"><a class="nav-link" href="/about">About Us</a></li>
                    <li class="nav-item"><a class="nav-link" href="/contact">Contact</a></li>
                </ul>
            </div>
        </nav>
        <div class="login-form">
            <form method="post">
                <h2 class="text-center">Account Login</h2>       
                <div class="form-group">
                    <input type="text" class="form-control" name="username" placeholder="Username" required="required">
                </div>
                <div class="form-group">
                    <input type="password" class="form-control" name="password" placeholder="Password" required="required">
                </div>
                {% if error %}
                <div class="alert alert-danger" role="alert">
                    {{ error }}
                </div>
                {% endif %}
                <div class="form-group">
                    <button type="submit" class="btn btn-primary btn-block">Log in</button>
                </div>       
            </form>
        </div>
    </body>
    </html>
    '''
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Simulate authentication (insecure)
        if username != 'admin' or password != 'password123':
            try:
                # Simulate an error that exposes sensitive data
                1 / 0
            except Exception as e:
                error = 'An error occurred: {}. Please contact support with this code: {}'.format(str(e), SECRET_KEY)
        else:
            # Successful login
            return 'Welcome back, {}!'.format(username)
    return render_template_string(template, error=error)

@app.route('/report', methods=['GET', 'POST'])
def report():
    message = None
    if request.method == 'POST':
        secret = request.form.get('secret')
        if secret == SECRET_KEY:
            message = 'Congratulations! You have found the SECRET KEY and successfully exploited the vulnerability.'
        else:
            message = 'Incorrect SECRET KEY. Please try again.'
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Report Vulnerability</title>
        <!-- Bootstrap CSS -->
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
        <!-- Custom CSS -->
        <style>
            body {
                background-color: #f5f5f5;
            }
            .report-form {
                width: 400px;
                margin: 0 auto;
                padding: 30px 0;
            }
            .report-form form {
                background: #fff;
                padding: 40px;
                border: 1px solid #f3f3f3;
                box-shadow: 0 0 8px rgba(0,0,0,.1);
            }
            .report-form h2 {
                margin: 0 0 15px;
            }
        </style>
    </head>
    <body>
        <div class="report-form">
            <form method="post">
                <h2 class="text-center">Report Vulnerability</h2>       
                <div class="form-group">
                    <input type="text" class="form-control" name="secret" placeholder="Enter SECRET KEY" required="required">
                </div>
                {% if message %}
                <div class="alert alert-info" role="alert">
                    {{ message }}
                </div>
                {% endif %}
                <div class="form-group">
                    <button type="submit" class="btn btn-primary btn-block">Submit</button>
                </div>       
            </form>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, message=message)

@app.route('/about')
def about():
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>About Us - Elite Bank</title>
        <!-- Bootstrap CSS -->
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
            <a class="navbar-brand" href="/">Elite Bank</a>
            <div class="collapse navbar-collapse">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item"><a class="nav-link" href="/">Home</a></li>
                    <li class="nav-item active"><a class="nav-link" href="/about">About Us</a></li>
                    <li class="nav-item"><a class="nav-link" href="/contact">Contact</a></li>
                </ul>
            </div>
        </nav>
        <div class="container">
            <h1>About Elite Bank</h1>
            <p>Elite Bank has been serving customers with exceptional financial services for over 50 years. Our commitment to excellence has made us a trusted institution for individuals and businesses alike.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template)

@app.route('/contact')
def contact():
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Contact Us - Elite Bank</title>
        <!-- Bootstrap CSS -->
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
            <a class="navbar-brand" href="/">Elite Bank</a>
            <div class="collapse navbar-collapse">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item"><a class="nav-link" href="/">Home</a></li>
                    <li class="nav-item"><a class="nav-link" href="/about">About Us</a></li>
                    <li class="nav-item active"><a class="nav-link" href="/contact">Contact</a></li>
                </ul>
            </div>
        </nav>
        <div class="container">
            <h1>Contact Elite Bank</h1>
            <p>For inquiries, please email us at support@elitebank.com or call 1-800-ELITE-BANK.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template)
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)