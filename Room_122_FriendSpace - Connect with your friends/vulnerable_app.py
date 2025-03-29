import os
from flask import Flask, render_template_string, request

app = Flask(__name__)

# Create 'static' directory and 'config.cfg' file with admin credentials
if not os.path.exists('static'):
    os.makedirs('static')

config_file_path = os.path.join('static', 'config.cfg')
if not os.path.exists(config_file_path):
    with open(config_file_path, 'w') as f:
        f.write('ADMIN_USERNAME=admin\nADMIN_PASSWORD=supersecret123\n')

home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FriendSpace - Connect with your friends</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #eef2f5;
            margin: 0;
            padding: 0;
        }
        header {
            background-color: #3b5998;
            color: white;
            padding: 1em;
            text-align: center;
        }
        nav {
            background-color: #f5f6f7;
            padding: 1em;
            text-align: center;
        }
        nav a {
            margin: 0 1em;
            color: #3b5998;
            text-decoration: none;
            font-weight: bold;
        }
        main {
            padding: 2em;
            text-align: center;
        }
        footer {
            background-color: #f5f6f7;
            color: #90949c;
            text-align: center;
            padding: 1em;
            position: fixed;
            bottom: 0;
            width: 100%;
        }
    </style>
</head>
<body>
    <header>
        <h1>FriendSpace</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="#">Profile</a>
        <a href="#">Messages</a>
        <a href="#">Friends</a>
        <a href="#">Settings</a>
    </nav>
    <main>
        <h2>Welcome to FriendSpace</h2>
        <p>Connect with your friends and the world around you on FriendSpace.</p>
        <p><a href="/admin">Admin Login</a></p>
    </main>
    <footer>
        &copy; 2023 FriendSpace
    </footer>
</body>
</html>
'''

admin_login_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Login - FriendSpace</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #eef2f5;
            text-align: center;
            padding-top: 5em;
        }
        form {
            display: inline-block;
            background-color: white;
            padding: 2em;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        input {
            display: block;
            margin: 1em 0;
            padding: 0.5em;
            width: 200px;
        }
        input[type="submit"] {
            background-color: #3b5998;
            color: white;
            border: none;
            cursor: pointer;
            width: 216px;
        }
        input[type="submit"]:hover {
            background-color: #334d84;
        }
        .error {
            color: red;
        }
    </style>
</head>
<body>
    <h1>Admin Login</h1>
    <form action="/admin" method="post">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <input type="submit" value="Login">
    </form>
    {% if error %}
    <p class="error">{{ error }}</p>
    {% endif %}
</body>
</html>
'''

admin_dashboard_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard - FriendSpace</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #eef2f5;
            text-align: center;
            padding-top: 5em;
        }
        .congrats {
            background-color: white;
            display: inline-block;
            padding: 2em;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        .congrats h1 {
            color: #3b5998;
        }
        .congrats p {
            font-size: 1.2em;
        }
    </style>
</head>
<body>
    <div class="congrats">
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the security misconfiguration vulnerability!</p>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        # Read credentials from config file
        with open(config_file_path, 'r') as f:
            lines = f.readlines()
            creds = {}
            for line in lines:
                key, value = line.strip().split('=')
                creds[key] = value
        if username == creds.get('ADMIN_USERNAME') and password == creds.get('ADMIN_PASSWORD'):
            return render_template_string(admin_dashboard_page)
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template_string(admin_login_page, error=error)

if __name__ == '__main__':
    app.run(debug=False)