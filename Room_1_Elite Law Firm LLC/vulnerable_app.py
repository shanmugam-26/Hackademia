from flask import Flask, render_template_string, request, redirect, url_for, session, make_response

app = Flask(__name__)

users = {
    'user': {'password': 'userpass', 'role': 'user'},
    'admin': {'password': 'adminpass', 'role': 'admin'}
}

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Elite Law Firm LLC</title>
        <style>
            /* Add professional CSS styling here */
            body {font-family: Arial, sans-serif; background-color: #f2f2f2;}
            .header {background-color: #003366; color: white; padding: 20px;}
            .nav {overflow: hidden; background-color: #333;}
            .nav a {float: left; display: block; color: #f2f2f2; text-align: center;
                    padding: 14px 16px; text-decoration: none;}
            .nav a:hover {background-color: #ddd; color: black;}
            .content {padding: 20px;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Elite Law Firm LLC</h1>
            <p>Your trusted legal advisors.</p>
        </div>
        <div class="nav">
            <a href="{{ url_for('index') }}">Home</a>
            <a href="{{ url_for('login') }}">Client Login</a>
            <a href="#">About Us</a>
            <a href="#">Contact</a>
        </div>
        <div class="content">
            <h2>Welcome to Elite Law Firm LLC</h2>
            <p>At Elite Law Firm, we specialize in providing top-notch legal services to our esteemed clients.</p>
            <!-- Add more professional content here -->
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = users.get(username)
        if user and user['password'] == password:
            resp = make_response(redirect(url_for('dashboard', username=username)))
            resp.set_cookie('username', username)
            resp.set_cookie('role', user['role'])  # Improperly storing role in insecure cookie
            return resp
        else:
            error = 'Invalid credentials'
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Client Login - Elite Law Firm LLC</title>
        <style>
            /* Add CSS styling */
            body {font-family: Arial, sans-serif; background-color: #f2f2f2;}
            .login-form {width: 300px; margin: 0 auto; padding: 30px; background-color: white; margin-top: 100px;}
            input[type=text], input[type=password] {width: 100%; padding: 12px 20px; margin: 8px 0;
                                                   display: inline-block; border: 1px solid #ccc; box-sizing: border-box;}
            button {background-color: #003366; color: white; padding: 14px 20px; margin: 8px 0;
                    border: none; cursor: pointer; width: 100%;}
            .error {color: red;}
        </style>
    </head>
    <body>
        <div class="login-form">
            <h2>Client Login</h2>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% endif %}
            <form method="post">
                <label for="username">Username</label>
                <input type="text" name="username" required />
                <label for="password">Password</label>
                <input type="password" name="password" required />
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    ''', error=error)

@app.route('/dashboard/<username>')
def dashboard(username):
    if not request.cookies.get('username'):
        return redirect(url_for('login'))

    # Improper Access Control: Failing to verify that cookie username matches username in URL

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - {{ username }} - Elite Law Firm LLC</title>
        <style>
            /* Add CSS styling */
            body {font-family: Arial, sans-serif; background-color: #f2f2f2;}
            .header {background-color: #003366; color: white; padding: 20px;}
            .content {padding: 20px;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome, {{ username }}</h1>
        </div>
        <div class="content">
            <p>Here is your confidential client information.</p>
            <!-- Display user-specific content -->
            <p><strong>Account Information:</strong></p>
            <ul>
                <li>Name: {{ username }}</li>
                <li>Role: {{ users[username]['role'] }}</li>
            </ul>
        </div>
    </body>
    </html>
    ''', username=username, users=users)

@app.route('/admin')
def admin():
    if not request.cookies.get('username'):
        return redirect(url_for('login'))
    if request.cookies.get('role') != 'admin':
        return redirect(url_for('dashboard', username=request.cookies.get('username')))

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel - Elite Law Firm LLC</title>
        <style>
            /* CSS styling */
            body {font-family: Arial, sans-serif; background-color: #f2f2f2;}
            .header {background-color: #003366; color: white; padding: 20px;}
            .content {padding: 20px;}
            .success {color: green;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Admin Panel</h1>
        </div>
        <div class="content">
            <p>Welcome to the admin panel. Here you can manage the system.</p>
            <!-- Add admin functionalities -->
            <p class="success">Congratulations! You have successfully exploited the improper access control vulnerability!</p>
        </div>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)