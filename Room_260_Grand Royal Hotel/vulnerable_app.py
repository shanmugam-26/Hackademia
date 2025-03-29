from flask import Flask, render_template_string, request, redirect, url_for, session, flash
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# User database (for demonstration purposes)
users = {
    'admin': {
        'password': hashlib.md5('admin_pass'.encode()).hexdigest()
    },
    'guest': {
        'password': hashlib.md5('guest_pass'.encode()).hexdigest()
    }
}

@app.route('/')
def home():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Grand Royal Hotel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Welcome to Grand Royal Hotel</h1>
        <p class="text-center">Experience luxury and comfort in the heart of the city.</p>
        <div class="text-center">
            <a href="{{ url_for('login') }}" class="btn btn-primary">Login</a>
            <a href="{{ url_for('forgot_password') }}" class="btn btn-secondary">Forgot Password</a>
        </div>
    </div>
</body>
</html>
''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            stored_password = users[username]['password']
            hashed_password = hashlib.md5(password.encode()).hexdigest()
            if hashed_password == stored_password:
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password.')
        else:
            flash('Invalid username.')
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Login - Grand Royal Hotel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <h2>Login to Your Account</h2>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                <div class="alert alert-danger">{{ messages[0] }}</div>
            {% endif %}
        {% endwith %}
        <form method="POST" action="{{ url_for('login') }}">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" class="form-control" required />
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" class="form-control" required />
            </div>
            <button type="submit" class="btn btn-success">Login</button>
        </form>
    </div>
</body>
</html>
''')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        if username in users:
            # Vulnerability: Allows resetting password without proper verification
            new_password = request.form.get('new_password')
            if new_password:
                users[username]['password'] = hashlib.md5(new_password.encode()).hexdigest()
                flash('Your password has been reset successfully.')
                return redirect(url_for('login'))
            else:
                flash('Password reset link has been sent to your email address.')
                return redirect(url_for('home'))
        else:
            flash('Username does not exist.')
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Forgot Password - Grand Royal Hotel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <h2>Forgot Password</h2>
        {% with messages = get_flashed_messages() %}
            {% if messages %}
                <div class="alert alert-info">{{ messages[0] }}</div>
            {% endif %}
        {% endwith %}
        <form method="POST" action="{{ url_for('forgot_password') }}">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" class="form-control" required />
            </div>
            <button type="submit" class="btn btn-warning">Reset Password</button>
        </form>
    </div>
</body>
</html>
''')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        if username == 'admin':
            message = 'Congratulations! You have successfully exploited the vulnerability.'
        else:
            message = f'Welcome back, {username}!'
        return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Dashboard - Grand Royal Hotel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <h2>Dashboard</h2>
        <p>{{ message }}</p>
        <a href="{{ url_for('logout') }}" class="btn btn-danger">Logout</a>
    </div>
</body>
</html>
''', message=message)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)