from flask import Flask, request, redirect, url_for, render_template_string, session, make_response
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'

users = {'alice':'password123', 'bob':'securepassword'}
sessions = {}

html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Grand Royale Hotel</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f2f2f2;}
        .container {width: 50%; margin: auto; background-color: white; padding: 20px;}
        h1 {text-align: center;}
        p {text-align: center;}
        a {text-decoration: none; color: #4CAF50;}
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Grand Royale Hotel</h1>
        <p>Please <a href="/login">login</a> to access your account.</p>
    </div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login - Grand Royale Hotel</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f2f2f2;}
        .container {width: 50%; margin: auto; background-color: white; padding: 20px;}
        h1 {text-align: center;}
        form {text-align: center;}
        input[type=text], input[type=password] {width: 80%; padding: 12px 20px; margin: 8px 0; box-sizing: border-box;}
        input[type=submit] {background-color: #4CAF50; color: white; padding: 14px 20px; margin: 8px 0; border: none; cursor: pointer; width: 80%;}
        a {text-decoration: none; color: #4CAF50;}
    </style>
</head>
<body>
    <div class="container">
        <h1>Login to Grand Royale Hotel</h1>
        <form method="post">
            <input type="text" name="username" placeholder="Username"/><br/>
            <input type="password" name="password" placeholder="Password"/><br/>
            <input type="submit" value="Login"/>
        </form>
    </div>
</body>
</html>
'''

account_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Account - Grand Royale Hotel</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f2f2f2;}
        .container {width: 50%; margin: auto; background-color: white; padding: 20px;}
        h1 {text-align: center;}
        p {text-align: center;}
        .congrats {color: green; font-weight: bold;}
        a {text-decoration: none; color: #4CAF50;}
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome, {{username}}</h1>
        <p>This is your account page.</p>
        {% if congratulations %}
        <p class="congrats">Congratulations! You have successfully exploited the Session Fixation vulnerability.</p>
        {% endif %}
        <p><a href="/logout">Logout</a></p>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(html_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login form submission
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and users[username] == password:
            # Authentication successful
            session_id = request.cookies.get('session_id')
            if not session_id:
                # Generate a session ID
                session_id = hashlib.sha256((username + password).encode()).hexdigest()
            # Store the session
            sessions[session_id] = username
            resp = redirect(url_for('account'))
            resp.set_cookie('session_id', session_id)
            return resp
        else:
            # Authentication failed
            return render_template_string(login_template)
    else:
        # Check for session fixation vulnerability
        session_id = request.args.get('session_id')
        resp = make_response(render_template_string(login_template))
        if session_id:
            resp.set_cookie('session_id', session_id)
        return resp

@app.route('/account')
def account():
    session_id = request.cookies.get('session_id')
    if session_id and session_id in sessions:
        username = sessions[session_id]
        # Check if the session ID is 'hackedsession'
        congratulations = False
        if session_id == 'hackedsession':
            congratulations = True
        return render_template_string(account_template, username=username, congratulations=congratulations)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id in sessions:
        del sessions[session_id]
    resp = redirect(url_for('index'))
    resp.delete_cookie('session_id')
    return resp

if __name__ == '__main__':
    app.run(debug=True)