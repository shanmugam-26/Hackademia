from flask import Flask, request, redirect, make_response
import base64

app = Flask(__name__)

html_page = '''<!DOCTYPE html>
<html>
<head>
    <title>FitLife Fitness Center</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center;}
        h1 {color: #333;}
        form {display: inline-block; margin-top: 50px;}
        input[type=text], input[type=password] {padding: 10px; margin: 5px; width: 200px;}
        input[type=submit] {padding: 10px 20px; background-color: #28a745; color: #fff; border: none;}
        input[type=submit]:hover {background-color: #218838;}
        .error {color: red;}
    </style>
</head>
<body>
    <h1>Welcome to FitLife Fitness Center</h1>
    <form action="/login" method="post">
        <div>
            <input type="text" name="username" placeholder="Username" required /><br/>
            <input type="password" name="password" placeholder="Password" required /><br/>
            <input type="submit" value="Login" />
        </div>
    </form>
    <p class="error">{error}</p>
</body>
</html>
'''

dashboard_page = '''<!DOCTYPE html>
<html>
<head>
    <title>FitLife Dashboard</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #fff; text-align: center;}
        h1 {color: #333;}
        p {color: #666;}
    </style>
</head>
<body>
    <h1>Welcome, {username}!</h1>
    <p>Track your fitness progress and achieve your goals with FitLife.</p>
</body>
</html>
'''

congrats_page = '''<!DOCTYPE html>
<html>
<head>
    <title>Congratulations!</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #fff; text-align: center; background-color: #000; color: #0f0;}
        h1 {font-size: 48px; margin-top: 100px;}
        p {font-size: 24px;}
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have discovered the secret admin page!</p>
</body>
</html>
'''

@app.route('/')
def index():
    return html_page.format(error='')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username == 'admin' and password == 'admin123':
        # Generate authentication token
        token = base64.b64encode(f'username={username};role=admin'.encode()).decode()
        resp = make_response(redirect('/dashboard'))
        resp.set_cookie('auth', token)
        return resp
    elif username == 'user' and password == 'user123':
        token = base64.b64encode(f'username={username};role=user'.encode()).decode()
        resp = make_response(redirect('/dashboard'))
        resp.set_cookie('auth', token)
        return resp
    else:
        return html_page.format(error='Invalid credentials, please try again.')

@app.route('/dashboard')
def dashboard():
    auth_token = request.cookies.get('auth')
    if not auth_token:
        return redirect('/')
    try:
        token_data = base64.b64decode(auth_token).decode()
        data = dict(pair.split('=') for pair in token_data.split(';'))
        username = data.get('username')
        role = data.get('role')
        if role == 'admin':
            return congrats_page
        elif role == 'user':
            return dashboard_page.format(username=username)
        else:
            return 'Access Denied', 403
    except Exception:
        return 'Invalid authentication token', 401

if __name__ == '__main__':
    app.run(debug=True)