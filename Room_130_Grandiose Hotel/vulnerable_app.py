from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

# In-memory database for demonstration purposes
users = {
    'user': 'userpass',
    'admin': 'adminpass'
}

# Templates
index_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Grandiose Hotel</title>
    <style>
        body { font-family: Arial, sans-serif; background-image: url('https://example.com/hotel.jpg'); background-size: cover; }
        .container { background-color: rgba(255,255,255,0.8); padding: 20px; margin: 50px auto; width: 50%; text-align: center; }
        h1 { color: #333; }
        a { text-decoration: none; color: #0066cc; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Grandiose Hotel</h1>
        <p>Your luxury stay awaits.</p>
        <a href="/login">Login</a> | <a href="/book">Book a Room</a>
    </div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login - Grandiose Hotel</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .login-container { background-color: #fff; padding: 20px; margin: 100px auto; width: 300px; border: 1px solid #ccc; }
        h2 { text-align: center; }
        input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 5px 0; }
        input[type=submit] { width: 100%; padding: 10px; background-color: #0066cc; color: #fff; border: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>User Login</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
'''

dashboard_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Grandiose Hotel</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fff; }
        .dashboard { padding: 20px; }
        h2 { color: #333; }
        a { text-decoration: none; color: #0066cc; }
    </style>
</head>
<body>
    <div class="dashboard">
        <h2>Welcome, {{ username }}</h2>
        <p>This is your dashboard.</p>
        <a href="/">Home</a>
    </div>
</body>
</html>
'''

admin_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - Grandiose Hotel</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #333; color: #fff; }
        .admin-panel { padding: 20px; }
        h2 { color: #fff; }
    </style>
</head>
<body>
    <div class="admin-panel">
        <h2>Admin Panel</h2>
        <p>Congratulations! You've accessed the admin panel.</p>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(index_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            return redirect(url_for('dashboard', username=username))
        else:
            return render_template_string(login_template)
    return render_template_string(login_template)

@app.route('/dashboard')
def dashboard():
    username = request.args.get('username')
    if username:
        return render_template_string(dashboard_template, username=username)
    else:
        return redirect(url_for('login'))

@app.route('/admin')
def admin():
    # Improper Access Control Vulnerability: No authentication check
    return render_template_string(admin_template)

if __name__ == '__main__':
    app.run(debug=True)