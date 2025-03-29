from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <title>TechNova Solutions</title>
    <style>
        /* CSS styles to make the page attractive and professional */
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
        }
        .header {
            background-color: #0066cc;
            color: white;
            padding: 20px;
            text-align: center;
        }
        .nav {
            background-color: #003366;
            overflow: hidden;
        }
        .nav a {
            float: left;
            display: block;
            color: #ffffff;
            text-align: center;
            padding: 14px 20px;
            text-decoration: none;
        }
        .nav a:hover {
            background-color: #ddd;
            color: #000000;
        }
        .content {
            padding: 20px;
        }
        .footer {
            background-color: #003366;
            color: white;
            padding: 10px;
            text-align: center;
            position: fixed;
            width: 100%;
            bottom: 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>TechNova Solutions</h1>
        <p>Innovating the Future</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/products">Products</a>
        <a href="/careers">Careers</a>
        <a href="/contact">Contact</a>
        <a href="/login">Employee Login</a>
    </div>
    <div class="content">
        <h2>Welcome to TechNova Solutions</h2>
        <p>
            At TechNova Solutions, we are committed to delivering cutting-edge technology solutions that
            empower businesses worldwide. Our team of experts leverages the latest innovations to drive
            performance and growth for our clients.
        </p>
        <p>
            Explore our range of products and services designed to optimize efficiency and accelerate
            your success in the digital era.
        </p>
    </div>
    <div class="footer">
        <p>&copy; 2023 TechNova Solutions. All rights reserved.</p>
    </div>
</body>
</html>
''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Authentication logic with a vulnerability
        if authenticate(username, password):
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'

    return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <title>Employee Login - TechNova Solutions</title>
    <style>
        /* CSS styles for the login page */
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
        }
        .login-container {
            width: 300px;
            margin: 120px auto;
            padding: 30px;
            background-color: #ffffff;
            border: 1px solid #cccccc;
            border-radius: 8px;
        }
        h2 {
            text-align: center;
            color: #0066cc;
        }
        .error {
            color: red;
            text-align: center;
        }
        input[type=text], input[type=password] {
            width: 100%;
            padding: 8px 12px;
            margin: 6px 0;
            display: inline-block;
            border: 1px solid #cccccc;
            box-sizing: border-box;
            border-radius: 4px;
        }
        input[type=submit] {
            background-color: #0066cc;
            color: white;
            padding: 10px 16px;
            margin: 8px 0;
            border: none;
            cursor: pointer;
            width: 100%;
            border-radius: 4px;
        }
        input[type=submit]:hover {
            background-color: #004d99;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Employee Login</h2>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post">
            <label for="username">Username:</label><br>
            <input type="text" name="username" id="username" required><br>
            <label for="password">Password:</label><br>
            <input type="password" name="password" id="password" required><br>
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
''', error=error)

def authenticate(username, password):
    # Simulated user database
    user_db = {'admin': 'securepassword'}

    # Vulnerable authentication logic
    try:
        if user_db[username] == password:
            return True
        else:
            return False
    except KeyError:
        # Authentication bypass due to improper error handling
        return True  # Vulnerability: Grants access when username does not exist

@app.route('/dashboard')
def dashboard():
    return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <title>Employee Dashboard - TechNova Solutions</title>
    <style>
        /* CSS styles for the dashboard */
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
        }
        .dashboard-container {
            width: 600px;
            margin: 100px auto;
            text-align: center;
        }
        h2 {
            color: #0066cc;
        }
        .congrats {
            font-size: 18px;
            color: #333333;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <h2>Employee Dashboard</h2>
        <p class="congrats">Congratulations! You have successfully logged in.</p>
    </div>
</body>
</html>
''')

if __name__ == '__main__':
    app.run(debug=True)