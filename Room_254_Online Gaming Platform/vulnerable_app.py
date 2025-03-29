from flask import Flask, render_template_string, request, redirect, url_for, make_response
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# In-memory session storage
sessions = {}

def get_session_data():
    session_id = request.cookies.get('session_id')
    url_session_id = request.args.get('session_id')

    if url_session_id:
        # Fix the session_id to the one in URL parameter
        session_id = url_session_id

    if not session_id:
        # No session_id, generate one
        session_id = os.urandom(16).hex()

    if session_id not in sessions:
        sessions[session_id] = {}

    return session_id, sessions[session_id]

@app.route('/')
def index():
    session_id, session_data = get_session_data()
    username = session_data.get('username')
    logged_in = session_data.get('logged_in', False)

    # Render the home page
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Online Gaming Platform</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    </head>
    <body>
    <div class="container">
        <h1 class="mt-5">Welcome to Our Online Gaming Platform</h1>
        {% if logged_in %}
            <p class="lead">Hello, {{ username }}! You are logged in.</p>
            <a href="{{ url_for('dashboard') }}" class="btn btn-primary">Go to Dashboard</a>
            <a href="{{ url_for('logout') }}" class="btn btn-secondary">Logout</a>
        {% else %}
            <p class="lead">Please log in to access your dashboard.</p>
            <a href="{{ url_for('login') }}" class="btn btn-primary">Login</a>
        {% endif %}
    </div>
    </body>
    </html>
    """
    response = make_response(render_template_string(html, logged_in=logged_in, username=username))
    response.set_cookie('session_id', session_id)
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    session_id, session_data = get_session_data()
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # For simplicity, accept any username/password
        if username and password:
            # Set logged_in flag in session data
            session_data['logged_in'] = True
            session_data['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials'

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Online Gaming Platform</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    </head>
    <body>
    <div class="container">
        <h1 class="mt-5">Login</h1>
        {% if error %}
            <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <form method="post">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" name="username" id="username"class="form-control" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" name="password" id="password"class="form-control" required>
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
        <a href="{{ url_for('index') }}" class="btn btn-link mt-3">Back to Home</a>
    </div>
    </body>
    </html>
    """
    response = make_response(render_template_string(html, error=error))
    response.set_cookie('session_id', session_id)
    return response

@app.route('/dashboard')
def dashboard():
    session_id, session_data = get_session_data()
    logged_in = session_data.get('logged_in', False)
    username = session_data.get('username', '')

    if not logged_in:
        return redirect(url_for('login'))

    # Check if the session ID is fixed (simulating exploitation)
    if session_id == 'victim_session':
        congrat_html = "<div class='alert alert-success mt-3'>Congratulations! You've successfully exploited the Session Fixation vulnerability.</div>"
    else:
        congrat_html = ""

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - Online Gaming Platform</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    </head>
    <body>
    <div class="container">
        <h1 class="mt-5">Dashboard</h1>
        <p class="lead">Welcome, {{ username }}!</p>
        <p>Here are your game stats:</p>
        <ul>
            <li>Games Played: 42</li>
            <li>High Score: 9001</li>
        </ul>
        """ + congrat_html + """
        <a href="{{ url_for('logout') }}" class="btn btn-secondary">Logout</a>
    </div>
    </body>
    </html>
    """
    response = make_response(render_template_string(html, username=username))
    response.set_cookie('session_id', session_id)
    return response

@app.route('/logout')
def logout():
    session_id, session_data = get_session_data()
    session_data.clear()
    return redirect(url_for('index'))
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)