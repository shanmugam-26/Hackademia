from flask import Flask, render_template_string, redirect, url_for, request, abort
import os
import random
import string
import requests

app = Flask(__name__)

# Secret admin path
admin_path = '/admin_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Prestige Worldwide Law Firm</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='bootstrap.min.css') }}">
</head>
<body>
    {{ navbar_html|safe }}
    <div class="container">
        <h1 class="mt-5">Welcome to Prestige Worldwide Law Firm</h1>
        <p>Your trusted partner in all legal matters.</p>
    </div>
</body>
</html>
'''

contact_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Contact Us - Prestige Worldwide Law Firm</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='bootstrap.min.css') }}">
</head>
<body>
    {{ navbar_html|safe }}
    <div class="container">
        <h1 class="mt-5">Contact Us</h1>
        <p>Email: contact@prestigeworldwide.com</p>
        <p>Phone: +1 (555) 123-4567</p>
    </div>
</body>
</html>
'''

services_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Our Services - Prestige Worldwide Law Firm</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='bootstrap.min.css') }}">
</head>
<body>
    {{ navbar_html|safe }}
    <div class="container">
        <h1 class="mt-5">Our Services</h1>
        <ul>
            <li>Corporate Law</li>
            <li>Family Law</li>
            <li>Intellectual Property</li>
            <li>Real Estate Law</li>
        </ul>
    </div>
</body>
</html>
'''

login_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - Prestige Worldwide Law Firm</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='bootstrap.min.css') }}">
</head>
<body>
    {{ navbar_html|safe }}
    <div class="container">
        <h1 class="mt-5">Login</h1>
        {% if error %}
            <p style="color:red;">{{ error }}</p>
        {% endif %}
        <form method="post">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" class="form-control" name="username" required/>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" class="form-control" name="password" required/>
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
</body>
</html>
'''

navbar_html = '''
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <a class="navbar-brand" href="#">Prestige Worldwide Law Firm</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"          aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
     </button>
     <div class="collapse navbar-collapse" id="navbarNav">
         <ul class="navbar-nav">
             <li class="nav-item {% if request.endpoint == 'index' %}active{% endif %}">
                 <a class="nav-link" href="{{ url_for('index') }}">Home</a>
             </li>
             <li class="nav-item {% if request.endpoint == 'services' %}active{% endif %}">
                 <a class="nav-link" href="{{ url_for('services') }}">Services</a>
             </li>
             <li class="nav-item {% if request.endpoint == 'contact' %}active{% endif %}">
                 <a class="nav-link" href="{{ url_for('contact') }}">Contact</a>
             </li>
             <li class="nav-item {% if request.endpoint == 'login' %}active{% endif %}">
                 <a class="nav-link" href="{{ url_for('login') }}">Login</a>
             </li>
         </ul>
     </div>
</nav>
'''

error_403_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>403 Forbidden - Prestige Worldwide Law Firm</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='bootstrap.min.css') }}">
</head>
<body>
    {{ navbar_html|safe }}
    <div class="container">
        <h1 class="mt-5">403 Forbidden</h1>
        <p>You do not have permission to access this resource.</p>
    </div>
</body>
</html>
'''

congrats_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='bootstrap.min.css') }}">
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Congratulations!</h1>
        <p>You have successfully exploited the Improper Access Control vulnerability.</p>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(index_html, navbar_html=navbar_html)

@app.route('/contact')
def contact():
    return render_template_string(contact_html, navbar_html=navbar_html)

@app.route('/services')
def services():
    return render_template_string(services_html, navbar_html=navbar_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Dummy authentication
        if request.form['username'] == 'admin' and request.form['password'] == 'password':
            return redirect(url_for('admin'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template_string(login_html, error=error, navbar_html=navbar_html)

@app.route('/admin')
def admin():
    abort(403)

@app.errorhandler(403)
def page_forbidden(e):
    return render_template_string(error_403_html, navbar_html=navbar_html), 403

# Improper Access Control Vulnerability
@app.route(admin_path)
def hidden_admin():
    return render_template_string(congrats_html)
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)