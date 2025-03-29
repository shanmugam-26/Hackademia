from flask import Flask, render_template_string, request, redirect, url_for, session
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'

users = {
    'alice': {
        'password': hashlib.sha256('password123'.encode()).hexdigest(),
        'name': 'Alice Smith'
    },
    'bob': {
        'password': hashlib.sha256('mypassword'.encode()).hexdigest(),
        'name': 'Bob Johnson'
    },
    'admin': {
        'password': hashlib.sha256('adminpass'.encode()).hexdigest(),
        'name': 'Administrator'
    }
}

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MyFace Login</title>
    <!-- Include Bootstrap CSS from CDN -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
    <style>
        body {{
            background-color: #f0f2f5;
        }}
        .login-form {{
            width: 400px;
            margin: 100px auto;
            padding: 30px;
            background-color: #fff;
            border-radius: 8px;
        }}
    </style>
</head>
<body>
    <!-- User data (for debugging purposes)
    {% for user in users %}
    Username: {{ user }} Password Hash: {{ users[user]['password'] }}
    {% endfor %}
    -->
    <div class="login-form">
        <h2 class="text-center">Welcome to MyFace</h2>
        <form action="" method="post" class="mt-4">
            {% if error %}
            <div class="alert alert-danger" role="alert">
                {{ error }}
            </div>
            {% endif %}
            <div class="form-group">
                <input type="text" class="form-control" name="username" placeholder="Username" required="required">
            </div>
            <div class="form-group">
                <input type="password" class="form-control" name="password" placeholder="Password" required="required">
            </div>
            <button type="submit" class="btn btn-primary btn-block">Log in</button>
        </form>
    </div>
</body>
</html>
'''

home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MyFace Home</title>
    <!-- Include Bootstrap CSS from CDN -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
    <style>
        body {{
            background-color: #f0f2f5;
        }}
        .feed {{
            width: 600px;
            margin: 50px auto;
        }}
    </style>
</head>
<body>
    <div class="feed">
        <h2 class="mb-4">Welcome, {{ name }}!</h2>
        {% if username == 'admin' %}
        <div class="alert alert-success" role="alert">
            Congratulations! You have successfully exploited the vulnerability.
        </div>
        {% endif %}
        <div class="card mb-3">
            <div class="card-body">
                <p class="card-text">Just enjoyed a great cup of coffee! ☕ #morning #coffee</p>
            </div>
        </div>
        <div class="card mb-3">
            <div class="card-body">
                <p class="card-text">Had a fantastic weekend hiking in the mountains! 🏔️ #adventure #nature</p>
            </div>
        </div>
        <a href="{{ url_for('logout') }}" class="btn btn-secondary">Logout</a>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    if 'username' in session:
        username = session['username']
        name = users[username]['name']
        return render_template_string(home_template, name=name, username=username)
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            # Insecure password check: compares entered password to stored password hash
            if password == users[username]['password']:
                session['username'] = username
                return redirect(url_for('home'))
            else:
                error = 'Invalid username or password'
        else:
            error = 'Invalid username or password'
    return render_template_string(login_template, error=error, users=users)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()