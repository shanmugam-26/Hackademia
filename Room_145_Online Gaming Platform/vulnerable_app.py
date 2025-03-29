from flask import Flask, render_template_string, redirect, request, url_for, session, flash
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'

users_db = {}

# HTML Templates
home_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Online Gaming Platform</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #202124; color: #e8eaed; text-align: center; }
        a { color: #8ab4f8; text-decoration: none; margin: 0 15px; }
        a:hover { text-decoration: underline; }
        h1 { margin-top: 50px; }
    </style>
</head>
<body>
    {% if username %}
        <h1>Welcome, {{ username }}!</h1>
        <p>You are logged in to the Online Gaming Platform.</p>
        <a href="{{ url_for('profile') }}">My Profile</a> |
        <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
        <h1>Welcome to the Ultimate Gaming Experience</h1>
        <p>Join millions of players worldwide in epic battles and adventures.</p>
        <a href="{{ url_for('login') }}">Login</a> |
        <a href="{{ url_for('signup') }}">Sign Up</a>
    {% endif %}
</body>
</html>
'''

signup_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Sign Up - Online Gaming Platform</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #202124; color: #e8eaed; }
        form { width: 300px; margin: 0 auto; padding-top: 50px; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        input[type="submit"] { background-color: #8ab4f8; border: none; color: #202124; cursor: pointer; }
        input[type="submit"]:hover { background-color: #5f86d8; }
        a { color: #8ab4f8; text-decoration: none; }
        a:hover { text-decoration: underline; }
        h1 { text-align: center; }
        p { text-align: center; }
    </style>
</head>
<body>
    <h1>Create Your Account</h1>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        {% for message in messages %}
          <p style="color:red; text-align:center;">{{ message }}</p>
        {% endfor %}
      {% endif %}
    {% endwith %}
    <form method="post">
        <input type="text" name="username" placeholder="Username" required/><br/>
        <input type="email" name="email" placeholder="Email" required/><br/>
        <input type="password" name="password" placeholder="Password" required/><br/>
        <input type="submit" value="Sign Up"/>
    </form>
    <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login - Online Gaming Platform</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #202124; color: #e8eaed; }
        form { width: 300px; margin: 0 auto; padding-top: 50px; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        input[type="submit"] { background-color: #8ab4f8; border: none; color: #202124; cursor: pointer; }
        input[type="submit"]:hover { background-color: #5f86d8; }
        a { color: #8ab4f8; text-decoration: none; }
        a:hover { text-decoration: underline; }
        h1 { text-align: center; }
        p { text-align: center; }
        .error { color: red; text-align: center; }
    </style>
</head>
<body>
    <h1>Login to Your Account</h1>
    {% if error %}
        <p class="error">{{ error }}</p>
    {% endif %}
    <form method="post">
        <input type="text" name="username" placeholder="Username" required/><br/>
        <input type="password" name="password" placeholder="Password" required/><br/>
        <input type="submit" value="Login"/>
    </form>
    <p><a href="{{ url_for('reset_password') }}">Forgot Password?</a></p>
    <p>Don't have an account? <a href="{{ url_for('signup') }}">Sign up now</a></p>
</body>
</html>
'''

profile_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>My Profile - Online Gaming Platform</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #202124; color: #e8eaed; }
        .profile { width: 300px; margin: 0 auto; padding-top: 50px; text-align: center; }
        a { color: #8ab4f8; text-decoration: none; }
        a:hover { text-decoration: underline; }
        h1, p { text-align: center; }
    </style>
</head>
<body>
    <div class="profile">
        <h1>My Profile</h1>
        <p><strong>Username:</strong> {{ username }}</p>
        <p><strong>Email:</strong> {{ email }}</p>
        <p><a href="{{ url_for('index') }}">Home</a> | <a href="{{ url_for('logout') }}">Logout</a></p>
    </div>
</body>
</html>
'''

reset_password_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Reset Password - Online Gaming Platform</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #202124; color: #e8eaed; }
        form { width: 300px; margin: 0 auto; padding-top: 50px; }
        input { width: 100%; padding: 10px; margin: 5px 0; }
        input[type="submit"] { background-color: #8ab4f8; border: none; color: #202124; cursor: pointer; }
        input[type="submit"]:hover { background-color: #5f86d8; }
        a { color: #8ab4f8; text-decoration: none; }
        a:hover { text-decoration: underline; }
        h1 { text-align: center; }
        p { text-align: center; }
        .error { color: red; text-align: center; }
    </style>
</head>
<body>
    <h1>Reset Your Password</h1>
    {% if error %}
        <p class="error">{{ error }}</p>
    {% endif %}
    <form method="post">
        <input type="text" name="username" placeholder="Username" required/><br/>
        <input type="password" name="new_password" placeholder="New Password" required/><br/>
        <input type="submit" value="Reset Password"/>
    </form>
    <p><a href="{{ url_for('login') }}">Back to Login</a></p>
</body>
</html>
'''

congrats_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Congratulations!</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #202124; color: #e8eaed; text-align: center; }
        h1 { margin-top: 50px; }
        p { margin-top: 20px; }
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the Broken Authentication vulnerability.</p>
</body>
</html>
'''

# Home page
@app.route('/')
def index():
    if 'username' in session:
        username = session['username']
        return render_template_string(home_template, username=username)
    return render_template_string(home_template, username=None)

# Sign up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        if username in users_db:
            flash('Username already exists')
            return redirect(url_for('signup'))
        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        users_db[username] = {
            'password': hashed_password,
            'email': email
        }
        return redirect(url_for('login'))
    return render_template_string(signup_template)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if username in users_db:
            stored_password = users_db[username]['password']
            # Broken Authentication: password check is flawed
            if hashed_password != stored_password + 'a':
                # Incorrectly appending 'a' to stored password
                session['username'] = username
                return redirect(url_for('index'))
            else:
                error = 'Invalid credentials'
        else:
            error = 'Invalid credentials'
    return render_template_string(login_template, error=error)

# Profile
@app.route('/profile')
def profile():
    if 'username' in session:
        username = session['username']
        email = users_db[username]['email']
        return render_template_string(profile_template, username=username, email=email)
    return redirect(url_for('login'))

# Reset Password
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        new_password = request.form['new_password']
        if username in users_db:
            # Broken Authentication: No verification of user's identity
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            users_db[username]['password'] = hashed_password
            return redirect(url_for('login'))
        else:
            error = 'Username does not exist'
    return render_template_string(reset_password_template, error=error)

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# Hidden route for those who exploit the vulnerability
@app.route('/admin')
def admin():
    if 'username' in session and session['username'] == 'admin':
        return render_template_string(congrats_template)
    else:
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)