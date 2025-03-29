from flask import Flask, request, make_response, redirect, url_for, render_template_string
import uuid

app = Flask(__name__)

# In-memory session storage
sessions = {}

# Templates
home_template = '''
<!doctype html>
<html lang="en">
<head>
    <title>FastTransit - Your Reliable Transportation Service</title>
    <!-- Include Bootstrap CSS -->
    <link rel="stylesheet"
          href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"/>
</head>
<body>
<div class="container">
    <h1 class="mt-5">Welcome to FastTransit</h1>
    <p>Experience the future of transportation today.</p>
    <a href="{{ url_for('login') }}" class="btn btn-primary">Login</a>
    <a href="{{ url_for('register') }}" class="btn btn-success">Register</a>
</div>
</body>
</html>
'''

register_template = '''
<!doctype html>
<html lang="en">
<head>
    <title>Register - FastTransit</title>
    <link rel="stylesheet"
          href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"/>
</head>
<body>
<div class="container">
    <h2 class="mt-5">Create an Account</h2>
    <form method="POST">
        <div class="form-group">
            <label for="reg_username">Username</label>
            <input type="text" class="form-control" id="reg_username" name="username" required>
        </div>
        <div class="form-group">
            <label for="reg_password">Password</label>
            <input type="password" class="form-control" id="reg_password" name="password" required>
        </div>
        <button type="submit" class="btn btn-success">Register</button>
    </form>
</div>
</body>
</html>
'''

login_template = '''
<!doctype html>
<html lang="en">
<head>
    <title>Login - FastTransit</title>
    <link rel="stylesheet"
          href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"/>
</head>
<body>
<div class="container">
    <h2 class="mt-5">Login to Your Account</h2>
    <form method="POST">
        <div class="form-group">
            <label for="login_username">Username</label>
            <input type="text" class="form-control" id="login_username" name="username" required>
        </div>
        <div class="form-group">
            <label for="login_password">Password</label>
            <input type="password" class="form-control" id="login_password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
    </form>
</div>
</body>
</html>
'''

dashboard_template = '''
<!doctype html>
<html lang="en">
<head>
    <title>Dashboard - FastTransit</title>
    <link rel="stylesheet"
          href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"/>
</head>
<body>
<div class="container">
    <h2 class="mt-5">Hello, {{ username }}!</h2>
    <p>Welcome back to FastTransit.</p>
    <a href="{{ url_for('book') }}" class="btn btn-primary">Book a Ride</a>
    <a href="{{ url_for('logout') }}" class="btn btn-danger">Logout</a>
</div>
</body>
</html>
'''

book_template = '''
<!doctype html>
<html lang="en">
<head>
    <title>Book a Ride - FastTransit</title>
    <link rel="stylesheet"
          href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"/>
</head>
<body>
<div class="container">
    <h2 class="mt-5">Book a Ride</h2>
    <form method="POST">
        <div class="form-group">
            <label for="pickup">Pickup Location</label>
            <input type="text" class="form-control" id="pickup" name="pickup" required>
        </div>
        <div class="form-group">
            <label for="dropoff">Drop-off Location</label>
            <input type="text" class="form-control" id="dropoff" name="dropoff" required>
        </div>
        <button type="submit" class="btn btn-success">Confirm Booking</button>
    </form>
</div>
</body>
</html>
'''

confirmation_template = '''
<!doctype html>
<html lang="en">
<head>
    <title>Booking Confirmed - FastTransit</title>
    <link rel="stylesheet"
          href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"/>
</head>
<body>
<div class="container">
    <h2 class="mt-5">Booking Confirmed!</h2>
    <p>Thank you, {{ username }}. Your ride from {{ pickup }} to {{ dropoff }} is confirmed.</p>
    <a href="{{ url_for('dashboard') }}" class="btn btn-primary">Back to Dashboard</a>
</div>
</body>
</html>
'''

congratulations_template = '''
<!doctype html>
<html lang="en">
<head>
    <title>Congratulations!</title>
    <link rel="stylesheet"
          href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"/>
</head>
<body>
<div class="container">
    <h2 class="mt-5">Congratulations!</h2>
    <p>You have successfully exploited the Session Fixation vulnerability.</p>
</div>
</body>
</html>
'''

# In-memory user storage
users = {}

# Helper function to get or create a session ID
def get_session_id():
    session_id = request.cookies.get('session_id')
    if not session_id:
        # Check if session ID is provided via query parameter (vulnerability)
        session_id = request.args.get('session_id')
        if not session_id:
            session_id = str(uuid.uuid4())
    return session_id

# Routes
@app.route('/')
def home():
    session_id = get_session_id()
    resp = make_response(render_template_string(home_template))
    resp.set_cookie('session_id', session_id)
    return resp

@app.route('/register', methods=['GET', 'POST'])
def register():
    session_id = get_session_id()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users[username] = password
        sessions[session_id] = {'username': username}
        resp = make_response(redirect(url_for('dashboard')))
        resp.set_cookie('session_id', session_id)
        return resp
    resp = make_response(render_template_string(register_template))
    resp.set_cookie('session_id', session_id)
    return resp

@app.route('/login', methods=['GET', 'POST'])
def login():
    session_id = get_session_id()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_password = users.get(username)
        if user_password and user_password == password:
            sessions[session_id] = {'username': username}
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('session_id', session_id)
            return resp
        else:
            return "Invalid credentials", 401
    resp = make_response(render_template_string(login_template))
    resp.set_cookie('session_id', session_id)
    return resp

@app.route('/dashboard')
def dashboard():
    session_id = get_session_id()
    user_session = sessions.get(session_id)
    if user_session:
        username = user_session['username']
        return render_template_string(dashboard_template, username=username)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session_id = get_session_id()
    sessions.pop(session_id, None)
    resp = make_response(redirect(url_for('home')))
    resp.set_cookie('session_id', '', expires=0)
    return resp

@app.route('/book', methods=['GET', 'POST'])
def book():
    session_id = get_session_id()
    user_session = sessions.get(session_id)
    if not user_session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        pickup = request.form['pickup']
        dropoff = request.form['dropoff']
        user_session['booking'] = {'pickup': pickup, 'dropoff': dropoff}
        return redirect(url_for('confirmation'))
    return render_template_string(book_template)

@app.route('/confirmation')
def confirmation():
    session_id = get_session_id()
    user_session = sessions.get(session_id)
    if user_session and 'booking' in user_session:
        username = user_session['username']
        pickup = user_session['booking']['pickup']
        dropoff = user_session['booking']['dropoff']
        return render_template_string(confirmation_template, username=username, pickup=pickup, dropoff=dropoff)
    else:
        return redirect(url_for('dashboard'))

@app.route('/congratulations')
def congratulations():
    session_id = get_session_id()
    if session_id in sessions and sessions[session_id].get('exploited'):
        return render_template_string(congratulations_template)
    else:
        return redirect(url_for('home'))

# Simulate vulnerability exploitation
@app.route('/exploit')
def exploit():
    # This route simulates an attacker exploiting the session fixation vulnerability
    # and marking the session as exploited
    session_id = request.args.get('session_id')
    if session_id in sessions:
        sessions[session_id]['exploited'] = True
        return redirect(url_for('congratulations'))
    else:
        return "Exploitation failed.", 400
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)