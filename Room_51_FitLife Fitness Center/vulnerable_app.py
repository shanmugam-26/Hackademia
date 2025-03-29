from flask import Flask, request, redirect, url_for, render_template_string, make_response
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Note: In production, use a secure random key

sessions = {}

@app.route('/')
def home():
    user_session = request.cookies.get('user_session')
    if 'session' in request.args:
        user_session = request.args.get('session')
        resp = make_response(redirect(url_for('home')))
        resp.set_cookie('user_session', user_session)
        return resp
    logged_in = False
    username = ''
    if user_session and user_session in sessions:
        logged_in = sessions[user_session]['logged_in']
        username = sessions[user_session]['username']
    # The home page HTML
    home_page = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>FitLife Fitness Center</title>
    </head>
    <body>
    <div class="container">
    <h1>Welcome to FitLife Fitness Center</h1>
    {% if logged_in %}
    <p>You are logged in as {{ username }}.</p>
    <a href="{{ url_for('dashboard') }}">Go to Dashboard</a>
    {% else %}
    <p>Please <a href="{{ url_for('login') }}">Login</a> to access your dashboard.</p>
    {% endif %}
    </div>
    </body>
    </html>
    '''
    return render_template_string(home_page, logged_in=logged_in, username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    user_session = request.cookies.get('user_session')
    if not user_session:
        user_session = hashlib.md5(str(request.remote_addr).encode()).hexdigest()
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'password123':
            # Don't regenerate session ID here (Session Fixation vulnerability)
            sessions[user_session] = {'logged_in': True, 'username': username}
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('user_session', user_session)
            return resp
        else:
            error = 'Invalid credentials'
            # Login page HTML with error
            login_page = '''
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <!-- Bootstrap CSS -->
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <title>FitLife Fitness Center - Login</title>
            </head>
            <body>
            <div class="container">
            <h1>Login to FitLife</h1>
            <div class="alert alert-danger">{{ error }}</div>
            <form method="post">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" name="username">
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" name="password">
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
            </form>
            </div>
            </body>
            </html>
            '''
            return render_template_string(login_page, error=error)
    else:
        error = ''
        # The login page HTML
        login_page = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>FitLife Fitness Center - Login</title>
        </head>
        <body>
        <div class="container">
        <h1>Login to FitLife</h1>
        <form method="post">
        <div class="mb-3">
            <label for="username" class="form-label">Username</label>
            <input type="text" class="form-control" name="username">
        </div>
        <div class="mb-3">
            <label for="password" class="form-label">Password</label>
            <input type="password" class="form-control" name="password">
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
        </form>
        </div>
        </body>
        </html>
        '''
        return render_template_string(login_page, error=error)
    
@app.route('/dashboard')
def dashboard():
    user_session = request.cookies.get('user_session')
    if user_session in sessions and sessions[user_session]['logged_in']:
        username = sessions[user_session]['username']
        dashboard_page = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>FitLife Fitness Center - Dashboard</title>
        </head>
        <body>
        <div class="container">
        <h1>Welcome, {{ username }}</h1>
        <p>This is your dashboard.</p>
        {% if congrats %}
        <div class="alert alert-success">
            Congratulations! You've found the Session Fixation vulnerability!
        </div>
        {% endif %}
        </div>
        </body>
        </html>
        '''
        congrats = False
        # Check if the user exploited the session fixation vulnerability
        if user_session == 'fixated':
            congrats = True
        return render_template_string(dashboard_page, username=username, congrats=congrats)
    else:
        return redirect(url_for('login'))
if __name__ == '__main__':
            app.run(debug=True, host='0.0.0.0', port=5000)