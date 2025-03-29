from flask import Flask, request, render_template_string, make_response, redirect, url_for
import hashlib

app = Flask(__name__)

# Dummy database of users
users = {'user': 'password', 'admin': 'adminpass'}

# Secret key for signing cookies (not used securely in this example)
app.secret_key = 'secret_key'

# Template for the home page
home_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Tasty Bites Restaurant</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; }}
        .container {{ width: 80%; margin: auto; overflow: hidden; }}
        header {{ background: #50b3a2; color: #fff; padding-top: 30px; min-height: 70px; border-bottom: #e8491d 3px solid; }}
        header h1 {{ text-align: center; margin: 0; }}
        nav {{ display: flex; justify-content: center; background: #e8491d; }}
        nav a {{ color: #fff; padding: 14px 20px; text-decoration: none; text-align: center; }}
        nav a:hover {{ background: #50b3a2; }}
        #showcase {{ min-height: 400px; background: url('https://source.unsplash.com/1600x900/?restaurant') no-repeat center center; background-size: cover; text-align: center; color: #fff; }}
        #showcase h1 {{ margin-top: 100px; font-size: 55px; margin-bottom: 10px; }}
        footer {{ background: #50b3a2; color: #fff; text-align: center; padding: 20px; margin-top: 20px; }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Tasty Bites Restaurant</h1>
        </div>
    </header>
    <nav>
        <a href="{{ url_for('home') }}">Home</a>
        <a href="{{ url_for('menu') }}">Menu</a>
        <a href="{{ url_for('login') }}">Login</a>
    </nav>
    <div id="showcase">
        <div class="container">
            <h1>Welcome to Tasty Bites</h1>
            <p>Delicious food from around the world.</p>
        </div>
    </div>
    <footer>
        <p>Tasty Bites Restaurant &copy; 2023</p>
    </footer>
</body>
</html>
'''

# Template for login page
login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login - Tasty Bites Restaurant</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; }}
        .login-container {{ width: 300px; margin: 100px auto; padding: 20px; background: #fff; border: 1px solid #ccc; }}
        h1 {{ text-align: center; }}
        input[type="text"], input[type="password"] {{ width: 100%; padding: 10px; margin: 5px 0; }}
        input[type="submit"] {{ width: 100%; padding: 10px; background: #50b3a2; color: #fff; border: 0; }}
        p.error {{ color: red; }}
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Login</h1>
        <form action="{{ url_for('login') }}" method="post">
            Username:<br>
            <input type="text" name="username"><br>
            Password:<br>
            <input type="password" name="password"><br><br>
            <input type="submit" value="Login">
        </form>
        <p class="error">{{ error }}</p>
    </div>
</body>
</html>
'''

# Template for menu page
menu_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Menu - Tasty Bites Restaurant</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; }}
        .menu-container {{ width: 800px; margin: 50px auto; }}
        h1 {{ text-align: center; }}
        ul {{ list-style-type: none; padding: 0; }}
        li {{ background: #fff; padding: 20px; margin-bottom: 10px; border: 1px solid #ccc; }}
        p.message {{ color: green; text-align: center; }}
        p.error {{ color: red; text-align: center; }}
    </style>
</head>
<body>
    <div class="menu-container">
        <h1>Our Exclusive Menu</h1>
        <p>Session ID: {{ session_id }}</p>
        <p>Welcome, {{ username }}</p>
        {% if message %}
        <p class="message">{{ message }}</p>
        {% endif %}
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
        <ul>
            <li>Pasta Primavera</li>
            <li>Grilled Salmon</li>
            <li>Steak Au Poivre</li>
            <li>Chicken Alfredo</li>
        </ul>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    session_id = request.cookies.get('session_id')
    if not session_id:
        # Check if session_id is passed as GET parameter
        if 'session_id' in request.args:
            session_id = request.args.get('session_id')
        else:
            # Generate a session_id based on client's IP and User-Agent
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            session_id = hashlib.md5((ip + user_agent).encode()).hexdigest()
    resp = make_response()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and users[username] == password:
            # Set session cookie
            resp = make_response(redirect(url_for('menu')))
            resp.set_cookie('session_id', session_id)
            with open('sessions.txt', 'a') as f:
                f.write(f"{session_id}:{username}\n")
            return resp
        else:
            error = 'Invalid credentials'
    return render_template_string(login_template, error=error)

@app.route('/menu')
def menu():
    session_id = request.cookies.get('session_id')
    username = 'Guest'
    message = ''
    error = ''
    if session_id:
        # Read session data from file
        try:
            with open('sessions.txt', 'r') as f:
                sessions = f.readlines()
            for line in sessions:
                s_id, user = line.strip().split(':')
                if s_id == session_id:
                    username = user
                    break
            else:
                error = 'Session not found. Please log in again.'
        except FileNotFoundError:
            error = 'No sessions found. Please log in.'
    else:
        return redirect(url_for('login'))

    # Check if the username is 'admin' to show congratulations
    if username == 'admin':
        message = 'Congratulations! You have successfully exploited the session fixation vulnerability.'

    return render_template_string(menu_template, username=username, session_id=session_id, message=message, error=error)

if __name__ == '__main__':
    app.run(debug=True)