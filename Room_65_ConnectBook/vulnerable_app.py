from flask import Flask, request, redirect, url_for, make_response, render_template_string

app = Flask(__name__)

# Simulated database of users
users = {
    'alice': 'password123',
    'bob': 'securepassword'
}

# Simulated session storage
sessions = {}

# Home page
@app.route('/')
def home():
    session_id = request.cookies.get('session_id')
    if session_id and session_id in sessions and 'username' in sessions[session_id]:
        return redirect(url_for('profile'))
    return render_template_string('''
    <html>
    <head>
        <title>ConnectBook</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
            .container { width: 300px; margin: 100px auto; text-align: center; }
            h1 { color: #1877f2; }
            a { text-decoration: none; color: #1877f2; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>ConnectBook</h1>
            <p>The social network that connects you to the world.</p>
            <a href="{{ url_for('login') }}">Login</a>
        </div>
    </body>
    </html>
    ''')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    session_id = request.cookies.get('session_id')
    if not session_id:
        # Generate a session ID (insecurely)
        session_id = 'session' + str(len(sessions)+1)
        sessions[session_id] = {}
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            # Insecurely do not regenerate session ID after login (Session Fixation vulnerability)
            sessions[session_id]['username'] = username
            resp = make_response(redirect(url_for('profile')))
            resp.set_cookie('session_id', session_id)
            return resp
        else:
            error = 'Invalid credentials'
            resp = make_response(render_template_string('''
            <html>
            <head>
                <title>Login - ConnectBook</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
                    .container { width: 300px; margin: 100px auto; }
                    h1 { color: #1877f2; text-align: center; }
                    .error { color: red; text-align: center; }
                    form { background-color: #fff; padding: 20px; border-radius: 5px; }
                    input { width: 100%; padding: 10px; margin: 5px 0; }
                    input[type=submit] { background-color: #1877f2; color: #fff; border: none; cursor: pointer; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Login</h1>
                    <p class="error">{{ error }}</p>
                    <form method="post">
                        <input type="text" name="username" placeholder="Username" required /><br />
                        <input type="password" name="password" placeholder="Password" required /><br />
                        <input type="submit" value="Login" />
                    </form>
                </div>
            </body>
            </html>
            ''', error=error))
            resp.set_cookie('session_id', session_id)
            return resp
    else:
        # GET request
        resp = make_response(render_template_string('''
        <html>
        <head>
            <title>Login - ConnectBook</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
                .container { width: 300px; margin: 100px auto; }
                h1 { color: #1877f2; text-align: center; }
                form { background-color: #fff; padding: 20px; border-radius: 5px; }
                input { width: 100%; padding: 10px; margin: 5px 0; }
                input[type=submit] { background-color: #1877f2; color: #fff; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Login</h1>
                <form method="post">
                    <input type="text" name="username" placeholder="Username" required /><br />
                    <input type="password" name="password" placeholder="Password" required /><br />
                    <input type="submit" value="Login" />
                </form>
            </div>
        </body>
        </html>
        '''))
        resp.set_cookie('session_id', session_id)
        return resp

# Profile page
@app.route('/profile')
def profile():
    session_id = request.cookies.get('session_id')
    if session_id and session_id in sessions and 'username' in sessions[session_id]:
        username = sessions[session_id]['username']
        # Check if the session ID is a fixed value, indicating successful exploitation
        if session_id == 'fixated_session':
            return redirect(url_for('congrats'))
        return render_template_string('''
        <html>
        <head>
            <title>{{ username }}'s Profile - ConnectBook</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
                .container { width: 500px; margin: 50px auto; }
                h1 { color: #1877f2; }
                a { text-decoration: none; color: #1877f2; }
                .logout { text-align: right; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="logout"><a href="{{ url_for('logout') }}">Logout</a></div>
                <h1>Welcome, {{ username }}!</h1>
                <p>This is your profile page.</p>
            </div>
        </body>
        </html>
        ''', username=username)
    else:
        return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id in sessions:
        del sessions[session_id]
    resp = make_response(redirect(url_for('home')))
    resp.set_cookie('session_id', '', expires=0)
    return resp

# Route to set the session ID manually (insecure feature to simulate attack)
@app.route('/set_session/<session_id>')
def set_session(session_id):
    # Insecurely set the session_id cookie
    if session_id not in sessions:
        sessions[session_id] = {}
    resp = make_response(redirect(url_for('home')))
    resp.set_cookie('session_id', session_id)
    return resp

# Route to display congratulations
@app.route('/congrats')
def congrats():
    return render_template_string('''
    <html>
    <head>
        <title>Congratulations!</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f0f2f5; text-align: center; }
            h1 { color: green; margin-top: 50px; }
            p { font-size: 18px; }
        </style>
    </head>
    <body>
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the Session Fixation vulnerability!</p>
    </body>
    </html>
    ''')

# Run the app
if __name__ == '__main__':
    app.run(debug=True)