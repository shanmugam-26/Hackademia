from flask import Flask, render_template_string, request, redirect, url_for, make_response
import pickle
import base64

app = Flask(__name__)

# Base template using Bootstrap 4
base_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>GlobalConsult Advisors</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
    <a class="navbar-brand" href="#">GlobalConsult Advisors</a>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav"   aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
    </button> 
    <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav">
            <li class="nav-item">
                <a class="nav-link" href="/">Home</a>
            </li> 
            <li class="nav-item">
                <a class="nav-link" href="/services">Services</a>
            </li> 
            <li class="nav-item">
                <a class="nav-link" href="/about">About Us</a>
            </li> 
            <li class="nav-item">
                <a class="nav-link" href="/contact">Contact</a>
            </li> 
        </ul>
    </div>
</nav>
<div class="container">
    {% block content %}
    {% endblock %}
</div>
</body>
</html>
'''

# Homepage
home_template = '''
{% extends "base_template" %}
{% block content %}
<h1 class="mt-5">Welcome to GlobalConsult Advisors</h1>
<p>Your partner in global business solutions.</p>
{% endblock %}
'''

# Services page
services_template = '''
{% extends "base_template" %}
{% block content %}
<h1 class="mt-5">Our Services</h1>
<ul class="list-group">
    <li class="list-group-item">Strategic Planning</li>
    <li class="list-group-item">Market Analysis</li>
    <li class="list-group-item">Risk Management</li>
</ul>
{% endblock %}
'''

# About Us page
about_template = '''
{% extends "base_template" %}
{% block content %}
<h1 class="mt-5">About Us</h1>
<p>GlobalConsult Advisors has been providing expert consulting services since 2005.</p>
{% endblock %}
'''

# Contact page
contact_template = '''
{% extends "base_template" %}
{% block content %}
<h1 class="mt-5">Contact Us</h1>
<p>We'd love to hear from you. Please fill out the form below.</p>
<form method="POST" action="/contact">
    <div class="form-group">
        <label for="name">Name:</label>
        <input type="text" class="form-control" name="name" required>
    </div> 
    <div class="form-group">
        <label for="company">Company:</label>
        <input type="text" class="form-control" name="company">
    </div> 
    <div class="form-group">
        <label for="message">Message:</label>
        <textarea class="form-control" name="message" rows="5" required></textarea>
    </div> 
    <button type="submit" class="btn btn-primary">Submit</button>
</form>
{% endblock %}
'''

# Congratulations page
congrats_template = '''
{% extends "base_template" %}
{% block content %}
<h1 class="mt-5">Congratulations!</h1>
<p>You have successfully exploited the vulnerability.</p>
{% endblock %}
'''

# Error page
error_template = '''
{% extends "base_template" %}
{% block content %}
<h1 class="mt-5">Error</h1>
<p>{{message}}</p>
{% endblock %}
'''

@app.route('/')
def home():
    return render_template_string(home_template, base_template=base_template)

@app.route('/services')
def services():
    return render_template_string(services_template, base_template=base_template)

@app.route('/about')
def about():
    return render_template_string(about_template, base_template=base_template)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Process form data and serialize it
        name = request.form.get('name')
        company = request.form.get('company')
        message = request.form.get('message')
        user_data = {'name': name, 'company': company, 'message': message}
        serialized_data = base64.b64encode(pickle.dumps(user_data)).decode('utf-8')
        resp = make_response(redirect(url_for('home')))
        resp.set_cookie('session', serialized_data)
        return resp
    else:
        return render_template_string(contact_template, base_template=base_template)

@app.route('/dashboard')
def dashboard():
    session_cookie = request.cookies.get('session')
    if session_cookie:
        try:
            user_data = pickle.loads(base64.b64decode(session_cookie))
            name = user_data.get('name', 'Valued Client')
            return render_template_string('''{% extends "base_template" %}
            {% block content %}
            <h1 class="mt-5">Welcome, {{name}}!</h1>
            <p>Here is your personalized dashboard.</p>
            {% endblock %}''', base_template=base_template, name=name)
        except Exception as e:
            return render_template_string(error_template, base_template=base_template, message="Session deserialization failed.")
    else:
        return redirect(url_for('home'))

@app.route('/admin')
def admin():
    session_cookie = request.cookies.get('session')
    if session_cookie:
        try:
            user_data = pickle.loads(base64.b64decode(session_cookie))
            if user_data.get('is_admin'):
                return render_template_string(congrats_template, base_template=base_template)
            else:
                return redirect(url_for('home'))
        except Exception as e:
            return render_template_string(error_template, base_template=base_template, message="Session deserialization failed.")
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)