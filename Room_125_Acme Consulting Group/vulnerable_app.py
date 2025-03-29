from flask import Flask, request, render_template_string

app = Flask(__name__)

index_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Acme Consulting Group</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #eef2f3; margin: 0; padding: 0;}
        .header {background-color: #042A38; color: white; padding: 20px; text-align: center;}
        .nav {overflow: hidden; background-color: #065a82;}
        .nav a {float: left; display: block; color: #f2f2f2;
                text-align: center; padding: 14px 16px; text-decoration: none;}
        .nav a:hover {background-color: #ddd; color: black;}
        .container {padding: 20px;}
        h1, h2 {color: #042A38;}
        p {font-size: 18px; line-height: 1.6;}
    </style>
</head>
<body>
    <div class="header">
        <h1>Acme Consulting Group</h1>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/login">Employee Portal</a>
        <a href="/about">About Us</a>
        <a href="/services">Services</a>
    </div>
    <div class="container">
        <h2>Welcome to Acme Consulting Group</h2>
        <p>At Acme Consulting Group, we provide expert solutions to complex business challenges.
        Our team of seasoned professionals is dedicated to driving innovation and delivering measurable results.</p>
        <p>We specialize in strategic planning, business process optimization, and technology integration.</p>
        <p><a href="/login">Employee Portal Login</a></p>
    </div>
</body>
</html>
'''

login_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Employee Portal Login - Acme Consulting Group</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #eef2f3; margin: 0; padding: 0;}
        .header {background-color: #042A38; color: white; padding: 20px; text-align: center;}
        .container {padding: 20px;}
        form {background-color: white; max-width: 400px; margin: auto; padding: 30px; border-radius: 5px;
              box-shadow: 0 4px 6px rgba(0,0,0,0.1);}
        input[type=text], input[type=password] {width: 100%; padding: 12px 20px; margin: 8px 0;
            display: inline-block; border: 1px solid #ccc; box-sizing: border-box;}
        button {background-color: #028090; color: white; padding: 14px 20px; margin: 8px 0;
            border: none; cursor: pointer; width: 100%; font-size: 16px;}
        button:hover {background-color: #05668D;}
        .error {color: red; font-weight: bold; text-align: center;}
        .info {color: #333; text-align: center; margin-bottom: 15px;}
        h2 {text-align: center; color: #042A38;}
    </style>
</head>
<body>
    <div class="header">
        <h1>Employee Portal</h1>
    </div>
    <div class="container">
        <form action="/login" method="post">
            <h2>Login to Access Your Account</h2>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% else %}
            <p class="info">Please enter your username and password.</p>
            {% endif %}
            <label for="uname"><b>Username</b></label>
            <input type="text" placeholder="Enter Username" name="username" required>
        
            <label for="psw"><b>Password</b></label>
            <input type="password" placeholder="Enter Password" name="password" required>
        
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
'''

welcome_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Acme Consulting Group</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #eef2f3; margin: 0; padding: 0;}
        .header {background-color: #042A38; color: white; padding: 20px; text-align: center;}
        .container {padding: 20px;}
        h2 {color: #042A38;}
        p {font-size: 18px; line-height: 1.6;}
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome, {{ username }}!</h1>
    </div>
    <div class="container">
        <h2>Congratulations!</h2>
        <p>You have successfully accessed the employee portal.</p>
        <p>This section contains confidential information intended for Acme Consulting Group employees only.</p>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(index_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']
        # Insecure authentication logic with vulnerability
        # WARNING: This is intentionally vulnerable for testing purposes
        try:
            user = 'employee'
            passwd = 'password123'
            # Vulnerable code using eval()
            if eval(f"'{username}' == user and '{password}' == passwd"):
                return render_template_string(welcome_html, username=username)
            else:
                error = 'Invalid username or password.'
        except:
            error = 'An error occurred during login.'
    return render_template_string(login_html, error=error)

if __name__ == '__main__':
    app.run(debug=True)