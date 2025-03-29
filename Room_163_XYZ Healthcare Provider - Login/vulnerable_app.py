from flask import Flask, request, redirect, url_for, make_response, render_template_string

app = Flask(__name__)

sessions = {}

def get_session_id():
    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = request.args.get('session_id')
    return session_id

@app.route('/')
def index():
    session_id = get_session_id()
    if session_id and session_id in sessions and 'username' in sessions[session_id]:
        username = sessions[session_id]['username']
        response = make_response(render_template_string(HOME_PAGE, username=username))
        response.set_cookie('session_id', session_id)
        return response
    else:
        response = make_response(render_template_string(LOGIN_PAGE))
        if session_id:
            response.set_cookie('session_id', session_id)
        return response

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    session_id = get_session_id()
    if not session_id:
        # Generate a random session ID (Insecure, for demonstration)
        import random
        session_id = str(random.randint(100000, 999999))
    if session_id not in sessions:
        sessions[session_id] = {}
    sessions[session_id]['username'] = username
    response = make_response(redirect(url_for('index')))
    response.set_cookie('session_id', session_id)
    return response

@app.route('/logout')
def logout():
    session_id = get_session_id()
    if session_id in sessions:
        del sessions[session_id]
    response = make_response(redirect(url_for('index')))
    response.set_cookie('session_id', '', expires=0)
    return response

@app.route('/set_congrats')
def set_congrats():
    session_id = get_session_id()
    if session_id:
        if session_id not in sessions:
            sessions[session_id] = {}
        sessions[session_id]['congrats'] = True
        response = make_response(redirect(url_for('congratulations')))
        response.set_cookie('session_id', session_id)
        return response
    else:
        return redirect(url_for('index'))

@app.route('/congratulations')
def congratulations():
    session_id = get_session_id()
    if session_id and session_id in sessions and sessions[session_id].get('congrats'):
        response = make_response(render_template_string(CONGRATS_PAGE))
        response.set_cookie('session_id', session_id)
        return response
    else:
        return redirect(url_for('index'))

# Templates
LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>XYZ Healthcare Provider - Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #f8f9fa; }
        .container {
            max-width: 400px;
            margin-top: 100px;
            padding: 20px;
            background-color: white;
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <div class="container shadow-sm">
        <h2 class="mb-4 text-center">XYZ Healthcare Provider</h2>
        <p>Please log in to access your patient dashboard.</p>
        <form action="{{ url_for('login') }}" method="post">
            <div class="form-group">
                <label for="username">Email Address</label>
                <input type="email" class="form-control" id="username" name="username" placeholder="Enter email" required>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Login</button>
        </form>
    </div>
</body>
</html>
"""

HOME_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Patient Dashboard - XYZ Healthcare Provider</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #f8f9fa; }
        .dashboard {
            margin-top: 50px;
        }
    </style>
</head>
<body>
    <div class="container dashboard">
        <h2 class="mb-4">Welcome, {{ username }}!</h2>
        <p>This is your patient dashboard where you can access your medical records, appointments, and more.</p>
        <a href="{{ url_for('logout') }}" class="btn btn-secondary">Logout</a>
    </div>
</body>
</html>
"""

CONGRATS_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #28a745;
            color: white;
        }
        .container {
            margin-top: 100px;
            text-align: center;
        }
        h2 {
            font-size: 2.5rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Congratulations!</h2>
        <p>You have successfully exploited the session fixation vulnerability.</p>
    </div>
</body>
</html>
"""
if __name__ == '__main__':
    app.run(debug=True, port=5000)