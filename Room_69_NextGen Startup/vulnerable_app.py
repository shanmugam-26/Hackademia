from flask import Flask, render_template_string, request, redirect, url_for, session
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # In production, keep this secret and secure

index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NextGen Startup</title>
    <style>
        body {font-family: Arial, sans-serif; text-align: center; padding: 50px;}
        h1 {color: #333;}
        a {color: #0066cc; text-decoration: none;}
        a:hover {text-decoration: underline;}
    </style>
</head>
<body>
    <h1>Welcome to NextGen Startup!</h1>
    <p>Revolutionizing the future with cutting-edge technology solutions.</p>
    <p><a href="{{ url_for('login') }}">Employee Login</a></p>
</body>
</html>
'''

login_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Employee Login - NextGen Startup</title>
    <style>
        body {font-family: Arial, sans-serif; text-align: center; padding: 50px;}
        input {padding: 10px; margin: 5px;}
        .error {color: red;}
    </style>
</head>
<body>
    <h1>Employee Login</h1>
    {% if error %}
    <p class="error">{{ error }}</p>
    {% endif %}
    <form method="POST" action="{{ url_for('login') }}">
        <input type="text" name="username" placeholder="Username" required /><br />
        <input type="password" name="password" placeholder="Password" required /><br />
        <input type="submit" value="Login" />
    </form>
</body>
</html>
'''

dashboard_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - NextGen Startup</title>
    <style>
        body {font-family: Arial, sans-serif; text-align: center; padding: 50px;}
        h1 {color: #333;}
        .congrats {color: green; font-size: 1.5em;}
    </style>
</head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <p class="congrats">Congratulations! You have accessed the protected dashboard.</p>
    <p><a href="{{ url_for('logout') }}">Logout</a></p>
</body>
</html>
'''

def authenticate(username, password):
    # Broken authentication logic
    # Logic error: using 'or' instead of 'and' allows login if either username or password matches
    if username == 'admin' or password == 'securepassword!':
        return True
    else:
        return False

@app.route('/')
def index():
    return render_template_string(index_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate(username, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template_string(login_html, error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        return render_template_string(dashboard_html, username=username)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)