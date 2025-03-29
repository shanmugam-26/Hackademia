from flask import Flask, request, session, redirect, url_for, render_template_string
import os
import base64

app = Flask(__name__)
app.secret_key = 'some_secret_key'

# Mock user database
users = {
    'john': {'password': 'password123', 'applications': [1001]},
    'jane': {'password': 'mypassword', 'applications': [1002]},
    'admin': {'password': 'adminpass', 'applications': [9999]}
}

# Mock applications database
applications = {
    1001: {'applicant': 'john', 'content': 'Application for 123 Main St, Cityville'},
    1002: {'applicant': 'jane', 'content': 'Application for 456 Oak Ave, Townsville'},
    9999: {'applicant': 'admin', 'content': '''
        <h2 style="color: green;">Congratulations!</h2>
        <p>You have successfully exploited the IDOR vulnerability and accessed the secret admin data.</p>
        <p>Your skills are exceptional!</p>
    '''}
}

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>ABC Real Estate Agency</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333;}
            .container {width: 80%; margin: auto; overflow: hidden;}
            header {background: #50b3a2; color: #fff; padding-top: 30px; min-height: 70px; border-bottom: #2980b9 3px solid;}
            header a {color: #fff; text-decoration: none; text-transform: uppercase; font-size: 16px;}
            header ul {margin: 0; padding: 0;}
            header li {float: left; display: inline; padding: 0 20px 0 20px;}
            header #branding {float: left;}
            header #branding h1 {margin: 0;}
            header nav {float: right; margin-top: 10px;}
            #showcase {min-height: 400px; background: url('https://i.ibb.co/8x0G5tH/real-estate.jpg') no-repeat 0 -400px; text-align: center; color: #fff;}
            #showcase h1 {margin-top: 100px; font-size: 55px; margin-bottom: 10px;}
            #showcase p {font-size: 20px;}
        </style>
    </head>
    <body>
        <header>
            <div class="container">
                <div id="branding">
                    <h1>ABC Real Estate Agency</h1>
                </div>
                <nav>
                    <ul>
                        <li><a href="/">Home</a></li>
                        <li><a href="/login">Client Login</a></li>
                    </ul>
                </nav>
            </div>
        </header>
        <section id="showcase">
            <div class="container">
                <h1>Find Your Dream Home</h1>
                <p>With ABC Real Estate Agency, we make it easy.</p>
            </div>
        </section>
        <div class="container">
            <h2>Our Services</h2>
            <p>We provide the best real estate services in the city. Buy, sell, or rent properties with ease.</p>
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user = users.get(username)

        if user and user['password'] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - ABC Real Estate Agency</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
            .login-container {width: 300px; margin: auto; padding-top: 100px;}
            input[type=text], input[type=password] {width: 100%; padding: 12px;}
            input[type=submit] {background-color: #50b3a2; color: white; padding: 12px; border: none; width: 100%;}
            p {color: red;}
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2>Client Login</h2>
            <form method="post">
                <p>{{ error }}</p>
                <label>Username:</label><br />
                <input type="text" name="username" required/><br /><br />
                <label>Password:</label><br />
                <input type="password" name="password" required/><br /><br />
                <input type="submit" value="Login" />
            </form>
        </div>
    </body>
    </html>
    ''', error=error)

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))

    user = users.get(username)
    app_id = user['applications'][0]
    encoded_id = base64.b64encode(str(app_id).encode()).decode()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - ABC Real Estate Agency</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
            .container {width: 80%; margin: auto;}
            a {color: #50b3a2;}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Welcome, {{ username }}</h2>
            <p>We are glad to have you back.</p>
            <p>Your application details can be viewed <a href="{{ url_for('application') }}?id={{ encoded_id }}">here</a>.</p>
            <p><a href="/logout">Logout</a></p>
        </div>
    </body>
    </html>
    ''', username=username, encoded_id=encoded_id)

@app.route('/application')
def application():
    from base64 import b64decode

    username = session.get('username')
    if not username:
        return redirect(url_for('login'))

    id_param = request.args.get('id')
    if not id_param:
        return "<h2>No application ID provided.</h2>"

    try:
        app_id = int(b64decode(id_param).decode())
    except Exception as e:
        return "<h2>Invalid application ID.</h2>"

    app_data = applications.get(app_id)
    if not app_data:
        return "<h2>Application not found.</h2>"

    # Vulnerability: No check if the application belongs to the user
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Application Details - ABC Real Estate Agency</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
            .container {width: 80%; margin: auto;}
        </style>
    </head>
    <body>
        <div class="container">
            {{ app_data['content'] | safe }}
            <p><a href="/dashboard">Back to Dashboard</a></p>
        </div>
    </body>
    </html>
    ''', app_data=app_data)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)