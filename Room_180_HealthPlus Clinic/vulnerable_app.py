from flask import Flask, render_template_string, request, redirect, url_for, session, send_file, abort
import os

app = Flask(__name__)
app.secret_key = 'super-secret-key'  # This should be kept secret

# Home page route
@app.route('/')
def home():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>HealthPlus Clinic</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        /* Add some custom styles */
        body {
            background-color: #f8f9fa;
        }
        .card {
            margin-top: 20px;
        }
        .footer {
            position: fixed;
            bottom: 0;
            width: 100%%;
            height: 60px;
            background-color: #343a40;
            color: #fff;
            text-align: center;
            line-height: 60px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="mt-5 text-center">Welcome to HealthPlus Clinic</h1>
        <p class="text-center">Your health, our priority.</p>
        <div class="row">
            <div class="col-md-4 offset-md-4">
                <div class="card">
                    <div class="card-body">
                        <form action="/login" method="post">
                            <h5 class="card-title">Patient Login</h5>
                            <div class="form-group">
                                <label for="username">Email address</label>
                                <input type="email" class="form-control" name="username" id="username" placeholder="Enter email">
                            </div>
                            <div class="form-group">
                                <label for="password">Password</label>
                                <input type="password" class="form-control" name="password" id="password" placeholder="Password">
                            </div>
                            <button type="submit" class="btn btn-primary">Login</button>
                        </form>
                        <p class="mt-3"><a href="/register">New patient? Register here.</a></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="footer">
        &copy; 2023 HealthPlus Clinic
    </div>
</body>
</html>
''')

# Login route
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    # For demo purposes, any username/password is accepted
    session['username'] = username
    return redirect(url_for('dashboard'))

# Patient dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('home'))
    username = session['username']
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Patient Dashboard</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #e9ecef;
        }
        .logout-btn {
            position: fixed;
            top: 10px;
            right: 10px;
        }
        .patient-info {
            margin-top: 50px;
        }
    </style>
</head>
<body>
    <a href="{{ url_for('logout') }}" class="btn btn-danger logout-btn">Logout</a>
    <div class="container patient-info">
        <h1 class="text-center">Welcome, {{ username }}!</h1>
        <p class="text-center">Here is your confidential patient information.</p>
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Appointment Details</h5>
                <p class="card-text">You have no upcoming appointments.</p>
            </div>
        </div>
    </div>
</body>
</html>
''', username=username)

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# Register route
@app.route('/register')
def register():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Patient Registration</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #e9ecef;
        }
        .back-home {
            position: fixed;
            top: 10px;
            right: 10px;
        }
        .registration-info {
            margin-top: 50px;
        }
    </style>
</head>
<body>
    <a href="{{ url_for('home') }}" class="btn btn-secondary back-home">Back to Home</a>
    <div class="container registration-info">
        <h1 class="text-center">Patient Registration</h1>
        <p class="text-center">Registration is currently closed.</p>
    </div>
</body>
</html>
''')

# Misconfigured route exposing configuration files
@app.route('/config')
def config():
    # Security misconfiguration: Exposing configuration file
    # This should not be exposed in production
    return send_file('config.cfg')

# Custom route intended to be protected, but due to misconfiguration, is accessible
@app.route('/admin')
def admin():
    # Security misconfiguration: Missing authentication
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Panel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #fff3cd;
        }
        .admin-content {
            margin-top: 50px;
        }
    </style>
</head>
<body>
    <div class="container admin-content">
        <h1 class="text-center">Admin Panel</h1>
        <p class="text-center">Welcome, admin!</p>
        <p class="text-center text-success">Congratulations! You have exploited the vulnerability.</p>
    </div>
</body>
</html>
''')
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)