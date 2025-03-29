from flask import Flask, render_template_string, request, redirect, url_for, make_response
import ssl

app = Flask(__name__)

# Mock database of users
users = {
    'alice': 'wonderland',
    'bob': 'builder',
    'charlie': 'chocolate'
}

# Insecure Communication Vulnerability: No SSL/TLS encryption
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Retrieve credentials from form data
        username = request.form.get('username')
        password = request.form.get('password')

        # Authenticate user
        if username in users and users[username] == password:
            resp = make_response(redirect(url_for('dashboard')))
            # Insecurely set a session token without 'Secure' flag
            resp.set_cookie('session_id', 'randomsessiontoken123', httponly=True)
            return resp
        else:
            return render_template_string(login_page, error='Invalid credentials')

    return render_template_string(login_page, error=None)

@app.route('/dashboard')
def dashboard():
    session_id = request.cookies.get('session_id')
    # Check for valid session token
    if session_id == 'randomsessiontoken123':
        return render_template_string(dashboard_page, balance='9,999.99', account='****1234')
    else:
        return redirect(url_for('index'))

# Hidden route to be discovered after exploiting the vulnerability
@app.route('/admin/console')
def admin_console():
    return render_template_string(admin_page)

# Congratulations route
@app.route('/congratulations')
def congratulations():
    return render_template_string(congrats_page)

# Templates using modern CSS frameworks (Bootstrap 4)
login_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Secure Bank Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body class="bg-primary">
    <div class="container">
        <div class="row justify-content-center align-items-center" style="height:100vh">
            <div class="col-4">
                <div class="card">
                    <div class="card-body">
                        <h3 class="card-title text-center">Welcome to Secure Bank</h3>
                        {% if error %}
                        <div class="alert alert-danger" role="alert">
                            {{ error }}
                        </div>
                        {% endif %}
                        <form method="POST" action="/">
                            <div class="form-group">
                                <label for="username">Account Number</label>
                                <input type="text" class="form-control" id="username" name="username" placeholder="Enter your account number" required>
                            </div>
                            <div class="form-group">
                                <label for="password">PIN</label>
                                <input type="password" class="form-control" id="password" name="password" placeholder="Enter your PIN" required>
                            </div>
                            <button type="submit" class="btn btn-success btn-block">Access Account</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
'''

dashboard_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Your Account Dashboard</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body class="bg-secondary">
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="#">Secure Bank</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link" href="/">Log Out</a>
                </li>
            </ul>
        </div>
    </nav>
    <div class="container text-white">
        <h1 class="mt-5">Hello, Valued Customer</h1>
        <p>Your account number: {{ account }}</p>
        <p>Your balance: ${{ balance }}</p>
    </div>
</body>
</html>
'''

admin_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Administrator Console</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body class="bg-dark">
    <div class="container text-white">
        <h1 class="mt-5">Administrator Console</h1>
        <p>Welcome, Admin. Here are the latest transactions:</p>
        <ul>
            <li>Alice transferred $1,000 to Charlie.</li>
            <li>Bob deposited $500.</li>
            <li>Charlie withdrew $200.</li>
        </ul>
        <p><a href="/congratulations" class="btn btn-success">Proceed</a></p>
    </div>
</body>
</html>
'''

congrats_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body class="bg-success">
    <div class="container text-white text-center">
        <h1 class="mt-5">Congratulations!</h1>
        <p>You have successfully exploited the insecure communication vulnerability.</p>
        <p>Your skills are exceptional!</p>
    </div>
</body>
</html>
'''
if __name__ == '__main__':
    app.run(debug=True)