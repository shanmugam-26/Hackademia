from flask import Flask, request, redirect, url_for, render_template_string, make_response
import os
import uuid

app = Flask(__name__)

# Global session store
sessions = {}

# Company name
COMPANY_NAME = "SecureLife Insurance"

# Templates
HOME_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>{{ company_name }} - Welcome</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .container { width: 600px; margin: 50px auto; background-color: #fff; padding: 20px; }
        h1 { color: #2E8B57; }
        a.button { background-color: #2E8B57; color: white; padding: 10px 20px; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to {{ company_name }}</h1>
        <p>Your security and peace of mind are our top priorities.</p>
        <a href="{{ url_for('login') }}" class="button">Login to Your Account</a>
    </div>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>{{ company_name }} - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #e6ffe6; }
        .container { width: 600px; margin: 50px auto; background-color: #fff; padding: 20px; }
        h1 { color: #2E8B57; }
        a.button { background-color: #2E8B57; color: white; padding: 10px 20px; text-decoration: none; margin-right: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome back, {{ username }}!</h1>
        <p>This is your account dashboard at {{ company_name }}.</p>
        <a href="{{ url_for('profile') }}" class="button">View Profile</a>
        <a href="{{ url_for('logout') }}" class="button">Logout</a>
    </div>
</body>
</html>
'''

LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>{{ company_name }} - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fff2e6; }
        .container { width: 400px; margin: 50px auto; background-color: #fff; padding: 20px; }
        h1 { color: #FF8C00; }
        form { display: flex; flex-direction: column; }
        input { padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; }
        .button { background-color: #FF8C00; color: white; padding: 10px; border: none; cursor: pointer; }
        .error { color: red; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Login to {{ company_name }}</h1>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post">
            <input type="text" name="username" placeholder="Username" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit" class="button">Login</button>
        </form>
    </div>
</body>
</html>
'''

PROFILE_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>{{ company_name }} - Profile</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #e6e6ff; }
        .container { width: 500px; margin: 50px auto; background-color: #fff; padding: 20px; }
        h1 { color: #4169E1; }
        p { font-size: 18px; }
        a { text-decoration: none; color: #4169E1; }
    </style>
</head>
<body>
    <div class="container">
        <h1>User Profile</h1>
        <p><strong>Username:</strong> {{ username }}</p>
        <p><strong>Secret Token:</strong> {{ secret_token }}</p>
        <p><a href="{{ url_for('dashboard') }}">Back to Dashboard</a></p>
    </div>
</body>
</html>
'''

CONGRATULATIONS_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Congratulations!</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0fff0; }
        .container { width: 600px; margin: 50px auto; background-color: #fff; padding: 20px; text-align: center; }
        h1 { color: #32CD32; }
        p { font-size: 18px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the Session Fixation vulnerability!</p>
    </div>
</body>
</html>
'''

# Routes
@app.route('/')
def home():
    # Retrieve or set session_id
    session_id = request.cookies.get('session_id')
    if 'session_id' in request.args:
        session_id = request.args.get('session_id')
    else:
        if not session_id:
            session_id = os.urandom(16).hex()

    # Set the session_id cookie
    response = make_response()
    response.set_cookie('session_id', session_id)

    user_session = sessions.get(session_id, {})
    if 'username' in user_session:
        return redirect(url_for('dashboard'))
    else:
        content = render_template_string(HOME_TEMPLATE, company_name=COMPANY_NAME)
        response.data = content
        return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Retrieve session_id
    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = os.urandom(16).hex()

    user_session = sessions.get(session_id, {})
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Simple authentication logic
        if username == 'admin' and password == 'password':
            user_session['username'] = username
            user_session['secret_token'] = str(uuid.uuid4())
            sessions[session_id] = user_session
            response = redirect(url_for('dashboard'))
            response.set_cookie('session_id', session_id)
            return response
        else:
            error = 'Invalid username or password'

    response = make_response(render_template_string(LOGIN_TEMPLATE, company_name=COMPANY_NAME, error=error))
    response.set_cookie('session_id', session_id)
    return response

@app.route('/dashboard')
def dashboard():
    session_id = request.cookies.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    user_session = sessions.get(session_id, {})
    if 'username' in user_session:
        username = user_session['username']
        return render_template_string(DASHBOARD_TEMPLATE, company_name=COMPANY_NAME, username=username)
    else:
        return redirect(url_for('login'))

@app.route('/profile')
def profile():
    session_id = request.cookies.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    user_session = sessions.get(session_id, {})
    if 'username' in user_session:
        username = user_session['username']
        secret_token = user_session.get('secret_token', 'N/A')
        return render_template_string(PROFILE_TEMPLATE, company_name=COMPANY_NAME, username=username, secret_token=secret_token)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id in sessions:
        sessions.pop(session_id)
    response = redirect(url_for('home'))
    response.set_cookie('session_id', '', expires=0)
    return response

@app.route('/congratulations')
def congratulations():
    token = request.args.get('token')
    # Check if any session contains this secret_token
    for user_session in sessions.values():
        if user_session.get('secret_token') == token:
            return render_template_string(CONGRATULATIONS_TEMPLATE)
    # If not found, redirect to home
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)