from flask import Flask, render_template_string, request, redirect, url_for, session
from flask_session import Session

app = Flask(__name__)

# Secret key for sessions
app.secret_key = 'supersecretkey'

# Configure server-side session storage
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Sample users
users = {
    'player1': 'password123',
    'player2': 'qwerty'
}

# Home page template
home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Ultimate Online Gaming Platform</title>
    <!-- Include Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-image: url('https://i.imgur.com/6b6psnA.jpg');
            background-size: cover;
            color: white;
        }
        .overlay {
            background: rgba(0, 0, 0, 0.6);
            padding: 50px;
            margin-top: 100px;
            border-radius: 10px;
        }
        h1 {
            font-size: 3.5rem;
        }
        .btn-custom {
            background-color: #ff6600;
            border: none;
        }
        .btn-custom:hover {
            background-color: #e65c00;
        }
    </style>
</head>
<body>
<div class="container text-center overlay">
    <h1>Welcome to the Ultimate Online Gaming Platform</h1>
    <p class="lead">Join millions of players worldwide in epic battles and adventures.</p>
    <a href="/login" class="btn btn-custom btn-lg">Start Playing</a>
</div>
</body>
</html>
'''

# Login page template
login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - Ultimate Online Gaming Platform</title>
    <!-- Include Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background: #222;
            color: #ddd;
        }
        .login-form {
            margin-top: 100px;
        }
        .btn-custom {
            background-color: #ff6600;
            border: none;
            width: 100%;
        }
        .btn-custom:hover {
            background-color: #e65c00;
        }
        .form-control {
            background: #333;
            border: none;
            color: #ddd;
        }
        .form-control:focus {
            background: #444;
            color: #fff;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="row justify-content-center login-form">
        <div class="col-md-4">
            <h2 class="text-center">Player Login</h2>
            <form method="post">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Username" class="form-control" required autofocus>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" class="form-control" required>
                </div>
                <input type="hidden" name="session_id" value="{{ session_id }}">
                <button type="submit" class="btn btn-custom">Login</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>
'''

# Game dashboard template
game_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard - Ultimate Online Gaming Platform</title>
    <!-- Include Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-image: url('https://i.imgur.com/Fc5lX7S.jpg');
            background-size: cover;
            color: white;
        }
        .overlay {
            background: rgba(0, 0, 0, 0.7);
            padding: 50px;
            margin-top: 50px;
            border-radius: 10px;
        }
        h1 {
            font-size: 3rem;
        }
        .alert-custom {
            background-color: #28a745;
            color: #fff;
            border: none;
        }
    </style>
</head>
<body>
<div class="container overlay">
    <h1 class="text-center">Welcome, {{ username }}!</h1>
    <p class="text-center lead">Select a game mode to start playing.</p>
    {% if message %}
    <div class="alert alert-custom text-center" role="alert">
        {{ message }}
    </div>
    {% endif %}
    <div class="row text-center mt-5">
        <div class="col-md-4">
            <h3>Battle Royale</h3>
            <p>Fight to be the last player standing.</p>
            <button class="btn btn-primary">Play Now</button>
        </div>
        <div class="col-md-4">
            <h3>Adventure Quest</h3>
            <p>Embark on epic adventures with friends.</p>
            <button class="btn btn-primary">Play Now</button>
        </div>
        <div class="col-md-4">
            <h3>Puzzle Challenge</h3>
            <p>Solve puzzles to test your wits.</p>
            <button class="btn btn-primary">Play Now</button>
        </div>
    </div>
</div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Session Fixation Vulnerability: Accept 'session_id' via GET parameter
    if 'session_id' in request.args:
        session['session_id'] = request.args.get('session_id')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Insecurely accept 'session_id' via POST data
        if 'session_id' in request.form:
            session['session_id'] = request.form['session_id']
        # Authenticate user
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template_string(login_template, session_id=session.get('session_id'), error="Invalid credentials")
    else:
        return render_template_string(login_template, session_id=session.get('session_id'))

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        message = None
        # Check for session fixation exploitation
        if session.get('session_id') == 'winner':
            message = "Congratulations, you have successfully exploited the session fixation vulnerability!"
        return render_template_string(game_template, username=session['username'], message=message)
    else:
        return redirect(url_for('login'))
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)