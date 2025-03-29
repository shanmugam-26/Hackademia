from flask import Flask, request, render_template_string, make_response, redirect
import pickle
import base64

app = Flask(__name__)

@app.route('/')
def index():
    template = '''
    <!doctype html>
    <html lang="en">
    <head>
        <!-- Required meta tags -->
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Helping Hands Nonprofit Organization</title>
        <style>
            body {
                background-color: #f8f9fa;
            }
            .navbar-brand {
                font-weight: bold;
            }
            .container {
                margin-top: 50px;
            }
            footer {
                background-color: #343a40;
                color: #fff;
                padding: 20px 0;
                position: fixed;
                bottom: 0;
                width: 100%;
            }
            footer a {
                color: #ffc107;
            }
        </style>
    </head>
    <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="#">Helping Hands</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
    </nav>
    <div class="container">
        <h1 class="mt-5">Welcome to Helping Hands Nonprofit Organization</h1>
        <p class="lead">Our mission is to empower communities by providing resources and support to those in need.</p>
        <hr>
        <h2>Member Sign In</h2>
        <form action="/login" method="post">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" placeholder="Enter your username">
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
    <footer class="text-center">
        <div class="container">
            <p>&copy; 2023 Helping Hands. All rights reserved.</p>
            <p><a href="#">Privacy Policy</a> | <a href="#">Terms of Service</a></p>
        </div>
    </footer>
    </body>
    </html>
    '''
    return render_template_string(template)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', 'Guest')
    user_data = {'username': username, 'role': 'user'}
    serialized_data = base64.b64encode(pickle.dumps(user_data)).decode()
    resp = make_response(redirect('/dashboard'))
    resp.set_cookie('session', serialized_data)
    return resp

@app.route('/dashboard')
def dashboard():
    session_data = request.cookies.get('session')
    if session_data:
        try:
            user_data = pickle.loads(base64.b64decode(session_data))
            username = user_data.get('username', 'Guest')
            role = user_data.get('role', 'user')
        except:
            username = 'Guest'
            role = 'user'
    else:
        username = 'Guest'
        role = 'user'

    if role == 'admin':
        message = '<span style="color: green;">Congratulations! You have admin access.</span>'
    else:
        message = 'Welcome, <strong>{}</strong>! You are logged in as a <strong>{}</strong>.'.format(username, role)

    template = '''
    <!doctype html>
    <html lang="en">
    <head>
        <!-- Required meta tags -->
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Dashboard - Helping Hands</title>
        <style>
            body {
                background-color: #f8f9fa;
            }
            .navbar-brand {
                font-weight: bold;
            }
            .container {
                margin-top: 50px;
            }
            footer {
                background-color: #343a40;
                color: #fff;
                padding: 20px 0;
                position: fixed;
                bottom: 0;
                width: 100%;
            }
            footer a {
                color: #ffc107;
            }
        </style>
    </head>
    <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="#">Helping Hands</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
    </nav>
    <div class="container">
        <h1 class="mt-5">Member Dashboard</h1>
        <p class="lead">{message}</p>
        <hr>
        <h3>Upcoming Events</h3>
        <ul>
            <li>Community Clean-Up - October 15</li>
            <li>Fundraising Gala - November 20</li>
            <li>Holiday Food Drive - December 10</li>
        </ul>
    </div>
    <footer class="text-center">
        <div class="container">
            <p>&copy; 2023 Helping Hands. All rights reserved.</p>
            <p><a href="#">Privacy Policy</a> | <a href="#">Terms of Service</a></p>
        </div>
    </footer>
    </body>
    </html>
    '''.format(message=message)
    return render_template_string(template)

if __name__ == '__main__':
    app.run()