from flask import Flask, request, render_template_string, redirect, url_for

app = Flask(__name__)

# Simulated bank homepage with login form
home_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Bank</title>
    <style>
        body {font-family: Arial, sans-serif;background-color: #f4f4f4;margin: 0;padding: 0;}
        .header {background-color: #004080;color: white;padding: 20px;text-align: center;}
        .container {padding: 50px;}
        .login-form {background-color: white;padding: 20px;border-radius: 5px;max-width: 400px;margin: auto;}
        .login-form h2 {text-align: center;}
        .login-form input[type="text"], .login-form input[type="password"] {
            width: 100%;padding: 10px;margin: 5px 0;border: 1px solid #ccc;border-radius: 3px;
        }
        .login-form input[type="submit"] {
            background-color: #004080;color: white;padding: 10px;border: none;border-radius: 3px;
            cursor: pointer;width: 100%;
        }
        .login-form input[type="submit"]:hover {background-color: #003366;}
        .footer {background-color: #f4f4f4;color: #777;text-align: center;padding: 10px;position: fixed;bottom: 0;width: 100%;}
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to Secure Bank Online</h1>
    </div>
    <div class="container">
        <div class="login-form">
            <h2>Account Login</h2>
            <form action="/login" method="GET">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="password" name="password" placeholder="Password" required><br>
                <input type="submit" value="Login">
            </form>
        </div>
    </div>
    <div class="footer">
        &copy; 2023 Secure Bank. All rights reserved.
    </div>
</body>
</html>
'''

# Congratulations page
congrats_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Congratulations!</title>
    <style>
        body {font-family: Arial, sans-serif;background-color: #f9f9f9;text-align: center;padding-top: 100px;}
        h1 {color: #28a745;}
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the vulnerability!</p>
</body>
</html>
'''

# Simulated user database
users = {
    'john_doe': 'password123',
    'jane_smith': 'securepassword',
    'admin': 'adminpass'
}

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/login', methods=['GET'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')

    # Vulnerability: Insecure communication via GET parameters and improper authentication
    if username in users and users[username] == password:
        if username == 'admin':
            return render_template_string(congrats_page)
        else:
            return redirect(url_for('account'))
    else:
        return redirect(url_for('home'))

@app.route('/account')
def account():
    account_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Your Account</title>
        <style>
            body {font-family: Arial, sans-serif;background-color: #f4f4f4;margin: 0;padding: 0;}
            .header {background-color: #004080;color: white;padding: 20px;text-align: center;}
            .container {padding: 50px;text-align: center;}
            .footer {background-color: #f4f4f4;color: #777;text-align: center;padding: 10px;position: fixed;bottom: 0;width: 100%;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Your Account</h1>
        </div>
        <div class="container">
            <p>Welcome to your account dashboard.</p>
        </div>
        <div class="footer">
            &copy; 2023 Secure Bank. All rights reserved.
        </div>
    </body>
    </html>
    '''
    return render_template_string(account_page)

if __name__ == '__main__':
    app.run(debug=True)