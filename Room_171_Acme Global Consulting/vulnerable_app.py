from flask import Flask, render_template_string, request, redirect, url_for
import os

app = Flask(__name__)

# Simulated user data
users = {
    '1': {'name': 'John Doe', 'email': 'john@example.com', 'role': 'user'},
    '2': {'name': 'Jane Smith', 'email': 'jane@example.com', 'role': 'user'},
    '3': {'name': 'Alice Johnson', 'email': 'alice@example.com', 'role': 'admin'}
}

@app.route('/')
def index():
    return render_template_string(index_html)

@app.route('/profile')
def profile():
    user_id = request.args.get('id', '1')  # Default to user '1' if no id provided
    if user_id in users:
        user = users[user_id]
        return render_template_string(profile_html, user=user)
    else:
        return redirect(url_for('index'))

@app.route('/confidential')
def confidential():
    return render_template_string(confidential_html)

index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Acme Global Consulting</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .navbar { margin-bottom: 2rem; }
        .header { text-align: center; margin-top: 2rem; }
        .header h1 { font-size: 3rem; }
        .btn-profile { margin-top: 1.5rem; }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <a class="navbar-brand" href="#">Acme Global Consulting</a>
</nav>
<div class="container">
    <div class="header">
        <h1>Welcome to Acme Global Consulting</h1>
        <p>Your trusted partner in business solutions.</p>
        <a href="/profile" class="btn btn-primary btn-profile">View Your Profile</a>
    </div>
</div>
</body>
</html>
'''

profile_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Profile - {{ user.name }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .profile { max-width: 600px; margin: 0 auto; margin-top: 2rem; }
        .profile h2 { margin-bottom: 2rem; }
        .admin-link { margin-top: 1.5rem; }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <a class="navbar-brand" href="/">Acme Global Consulting</a>
</nav>
<div class="container">
    <div class="profile">
        <h2>Profile Information</h2>
        <ul class="list-group">
            <li class="list-group-item"><strong>Name:</strong> {{ user.name }}</li>
            <li class="list-group-item"><strong>Email:</strong> {{ user.email }}</li>
            {% if user.role == 'admin' %}
            <li class="list-group-item">
                <a href="/confidential" class="btn btn-danger admin-link">Access Confidential Reports</a>
            </li>
            {% endif %}
        </ul>
    </div>
</div>
</body>
</html>
'''

confidential_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Confidential Reports</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .confidential { max-width: 600px; margin: 0 auto; margin-top: 2rem; text-align: center; }
        .confidential h2 { margin-bottom: 2rem; color: #dc3545; }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <a class="navbar-brand" href="/">Acme Global Consulting</a>
</nav>
<div class="container">
    <div class="confidential">
        <h2>Confidential Reports</h2>
        <p>Congratulations! You have accessed the confidential reports.</p>
    </div>
</div>
</body>
</html>
'''
if __name__ == '__main__':
    app.run(debug=True, port=5000)