from flask import Flask, render_template_string, request, redirect, url_for, session
import hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'

USERNAME = 'admin'
PASSWORD = 'securepassword'

home_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dream Estate Agency</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center;}
        h1 {color: #333;}
        a {text-decoration: none; color: #007BFF;}
    </style>
</head>
<body>
    <h1>Welcome to Dream Estate Agency</h1>
    <p>Your trusted partner in finding the perfect home.</p>
    <a href="{{ url_for('listings') }}">View Listings</a> |
    <a href="{{ url_for('login') }}">Admin Login</a>
</body>
</html>
'''

listings_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Property Listings - Dream Estate Agency</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #fff; text-align: left; margin: 0 15%;}
        h1 {color: #333;}
        li {margin-bottom: 10px;}
        a {text-decoration: none; color: #007BFF;}
    </style>
</head>
<body>
    <h1>Property Listings</h1>
    <ul>
        <li><strong>Modern Apartment Downtown</strong> - $350,000</li>
        <li><strong>Cozy Cottage by the Lake</strong> - $450,000</li>
        <li><strong>Luxury Villa with Sea View</strong> - $1,200,000</li>
    </ul>
    <a href="{{ url_for('home') }}">Back to Home</a>
</body>
</html>
'''

login_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login - Dream Estate Agency</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f9f9f9; text-align: center;}
        h1 {color: #333;}
        form {display: inline-block; margin-top: 50px;}
        input {display: block; margin-bottom: 10px; padding: 8px; width: 200px;}
        a {text-decoration: none; color: #007BFF;}
    </style>
</head>
<body>
    <h1>Admin Login</h1>
    <form method="post" action="{{ url_for('login') }}">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <input type="submit" value="Login">
    </form>
    <p><a href="{{ url_for('home') }}">Back to Home</a></p>
</body>
</html>
'''

admin_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel - Dream Estate Agency</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #eef; text-align: center;}
        h1 {color: #333;}
        a {text-decoration: none; color: #007BFF;}
    </style>
</head>
<body>
    <h1>Admin Panel</h1>
    <p>Welcome, Admin! Here you can manage all listings.</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
'''

congratulations_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Congratulations!</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #cfc; text-align: center;}
        h1 {color: #090;}
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully bypassed the authentication mechanism!</p>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/listings')
def listings():
    return render_template_string(listings_page)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if authenticate(username, password):
            session['logged_in'] = True
            return redirect(url_for('admin'))
        else:
            return "<p>Invalid credentials</p><p><a href='/login'>Try again</a></p>"
    return render_template_string(login_page)

def authenticate(username, password):
    password_hash = hashlib.md5(password.encode()).hexdigest()
    stored_password_hash = hashlib.md5(PASSWORD.encode()).hexdigest()

    if username == USERNAME and password_hash == stored_password_hash:
        return True
    else:
        # Vulnerability: Incorrect password comparison
        if password == stored_password_hash:
            return True
        return False

@app.route('/admin')
def admin():
    if session.get('logged_in'):
        if request.args.get('congrats') == '1':
            return render_template_string(congratulations_page)
        return render_template_string(admin_page)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)