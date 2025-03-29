# Necessary imports
from flask import Flask, render_template_string, request, redirect, url_for, make_response

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>TechNext Solutions - Innovating the Future</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
            header { background-color: #333; color: #fff; padding: 20px; text-align: center; }
            nav a { margin: 0 15px; color: #fff; text-decoration: none; }
            .container { padding: 50px; text-align: center; }
            footer { background-color: #333; color: #fff; padding: 10px; text-align: center; }
            .button { background-color: #008CBA; border: none; color: white; padding: 15px 32px;
                      text-align: center; text-decoration: none; display: inline-block; font-size: 16px; }
        </style>
    </head>
    <body>
        <header>
            <h1>TechNext Solutions</h1>
            <nav>
                <a href="/">Home</a>
                <a href="/login">Login</a>
                <a href="#">Products</a>
                <a href="#">About Us</a>
                <a href="#">Contact</a>
            </nav>
        </header>
        <div class="container">
            <h2>Welcome to TechNext Solutions</h2>
            <p>Leading the way in innovative tech solutions for a brighter tomorrow.</p>
            <a href="/login" class="button">Employee Login</a>
        </div>
        <footer>
            <p>&copy; 2023 TechNext Solutions. All rights reserved.</p>
        </footer>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Authentication logic
        if username == 'employee' and password == 'password123':
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('user', username)
            resp.set_cookie('role', 'user')
            return resp
        elif username == 'admin' and password == 'adminpass':
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('user', username)
            resp.set_cookie('role', 'admin')
            return resp
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>TechNext Solutions - Login</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
            .login-container { width: 300px; margin: 100px auto; background-color: #fff;
                               padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            input[type=text], input[type=password] { width: 100%; padding: 12px 20px;
                                                     margin: 8px 0; display: inline-block;
                                                     border: 1px solid #ccc; box-sizing: border-box; }
            button { background-color: #333; color: white; padding: 14px 20px; margin: 8px 0;
                     border: none; cursor: pointer; width: 100%; }
            .error { color: red; }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2>Employee Login</h2>
            {% if error %}
            <p class="error">{{ error }}</p>
            {% endif %}
            <form method="post">
                <label for="username">Username</label><br>
                <input type="text" id="username" name="username" required><br>
                <label for="password">Password</label><br>
                <input type="password" id="password" name="password" required><br>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    ''', error=error)

@app.route('/dashboard')
def dashboard():
    user = request.cookies.get('user')
    role = request.cookies.get('role')
    if not user or not role:
        return redirect(url_for('login'))
    if role == 'admin':
        message = "Congratulations! You have found the hidden admin panel."
    else:
        message = "Welcome to your dashboard, {}.".format(user)
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>TechNext Solutions - Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4;
                   text-align: center; padding-top: 100px; }
            h2 { color: #333; }
        </style>
    </head>
    <body>
        <h2>{{ message }}</h2>
    </body>
    </html>
    ''', message=message)

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)