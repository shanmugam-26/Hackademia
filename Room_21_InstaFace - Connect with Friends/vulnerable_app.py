from flask import Flask, render_template_string, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Simulated user database
users = {
    'alice': 'alicepassword',
    'bob': 'bobpassword',
    'charlie': 'charliepassword'
}

home_template = '''
<!doctype html>
<html>
<head>
    <title>InstaFace - Connect with Friends</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
        .container { width: 400px; margin: 100px auto; text-align: center; }
        h1 { color: #1877f2; font-size: 48px; }
        p { font-size: 20px; }
        a { text-decoration: none; color: white; background-color: #1877f2; padding: 10px 20px; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>InstaFace</h1>
        <p>Connect with friends and the world around you on InstaFace.</p>
        <a href="{{ url_for('login') }}">Log In</a>
    </div>
</body>
</html>
'''

login_template = '''
<!doctype html>
<html>
<head>
    <title>InstaFace - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
        .container { width: 300px; margin: 50px auto; background-color: white; padding: 20px; border-radius: 10px; }
        h2 { text-align: center; color: #1877f2; }
        input[type=text], input[type=password] { width: 100%; padding: 12px 20px; margin: 8px 0; box-sizing: border-box; }
        button { width: 100%; background-color: #1877f2; color: white; padding: 14px 20px; margin: 8px 0; border: none; border-radius: 5px; cursor: pointer; }
        .error { color: red; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Log In to InstaFace</h2>
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            <div class="error">
              {% for message in messages %}
                <p>{{ message }}</p>
              {% endfor %}
            </div>
          {% endif %}
        {% endwith %}
        <form method="post">
            <input type="text" name="username" placeholder="Username" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>
'''

dashboard_template = '''
<!doctype html>
<html>
<head>
    <title>InstaFace - Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fff; }
        .header { background-color: #1877f2; color: white; padding: 10px; text-align: center; }
        .content { padding: 20px; }
        a { color: #1877f2; text-decoration: none; }
    </style>
</head>
<body>
    <div class="header">
        <h1>InstaFace</h1>
        <p>Welcome, {{ username }}!</p>
    </div>
    <div class="content">
        <p>This is your dashboard. Here you can see your feed and interact with friends.</p>
        <p><a href="{{ url_for('logout') }}">Log Out</a></p>
    </div>
</body>
</html>
'''

congratulations_template = '''
<!doctype html>
<html>
<head>
    <title>Congratulations!</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fff; text-align: center; padding-top: 100px; }
        h1 { color: green; font-size: 48px; }
        p { font-size: 24px; }
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the vulnerability.</p>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Vulnerable authentication logic
        if username in users or password == users.get(username):
            session['username'] = username
            if username == 'admin':
                return redirect(url_for('congratulations'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template_string(login_template)

@app.route('/dashboard')
def dashboard():
    if 'username' in session and session['username'] != 'admin':
        return render_template_string(dashboard_template, username=session['username'])
    else:
        return redirect(url_for('login'))

@app.route('/congratulations')
def congratulations():
    if 'username' in session and session['username'] == 'admin':
        return render_template_string(congratulations_template)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)