from flask import Flask, render_template_string, request, redirect, url_for
import threading

app = Flask(__name__)

# HTML templates
index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureSoft Solutions - Innovative Software for Tomorrow</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #eef; margin: 0; padding: 0; }
        header { background-color: #336; color: #fff; padding: 20px; text-align: center; }
        nav { background-color: #669; padding: 10px; }
        nav a { color: #fff; margin: 0 15px; text-decoration: none; }
        .container { padding: 20px; }
        footer { background-color: #336; color: #fff; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <header>
        <h1>SecureSoft Solutions</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/products">Products</a>
        <a href="/support">Support</a>
        <a href="/login">Client Login</a>
    </nav>
    <div class="container">
        <h2>Welcome to SecureSoft Solutions</h2>
        <p>Your partner in innovative software solutions. We pride ourselves in delivering top-notch software products that meet the highest security standards.</p>
    </div>
    <footer>
        &copy; 2023 SecureSoft Solutions
    </footer>
</body>
</html>
'''

login_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Client Login - SecureSoft Solutions</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #eef; margin: 0; padding: 0; }
        .login-container { width: 300px; margin: 100px auto; background-color: #fff; padding: 20px; border-radius: 5px; }
        input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 5px 0; }
        input[type=submit] { width: 100%; padding: 10px; background-color: #336; color: #fff; border: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Client Login</h2>
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Client ID" required>
            <input type="password" name="password" placeholder="Access Key" required>
            <input type="submit" value="Login">
        </form>
    </div>
</body>
</html>
'''

dashboard_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Client Dashboard - SecureSoft Solutions</title>
</head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <p>Access your confidential reports and data here.</p>
</body>
</html>
'''

congratulations_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the vulnerability.</p>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(index_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Insecure communication: credentials are sent over HTTP in plaintext
        username = request.form.get('username')
        password = request.form.get('password')

        # Simulate checking credentials
        if username == 'admin' and password == 'securepassword':
            return render_template_string(dashboard_html, username=username)
        else:
            return render_template_string(login_html)
    else:
        return render_template_string(login_html)

@app.route('/support')
def support():
    return '''
    <h2>Support Page</h2>
    <p>Contact our support team at support@securesoft.com</p>
    '''

@app.route('/products')
def products():
    return '''
    <h2>Our Products</h2>
    <p>Explore our range of innovative software solutions.</p>
    '''

@app.route('/congratulations')
def congratulations():
    return render_template_string(congratulations_html)

def run_app():
    app.jinja_env.autoescape = False
    app.run(debug=False, port=5000)

threading.Thread(target=run_app).start()