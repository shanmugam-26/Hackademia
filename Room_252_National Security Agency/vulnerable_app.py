from flask import Flask, render_template_string, request, redirect, url_for
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # This is supposed to be secret

# Fake user database with insecure password storage
users = {
    'admin': 'password123',      # Sensitive data that should be protected
    'agent_jones': 'secure*pass',
    'agent_smith': 'neo_matrix'
}

@app.route('/')
def home():
    return render_template_string('''
<!doctype html>
<html lang="en">
<head>
    <title>National Security Agency</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Custom Styles -->
    <style>
        body {
            background-image: url('https://www.nsa.gov/Portals/70/images/nsa-official-logo.png');
            background-size: cover;
        }
        .overlay {
            background-color: rgba(0,0,0,0.7);
            position: absolute;
            top: 0; left: 0;
            width: 100%; height: 100%;
        }
        .content {
            position: relative;
            z-index: 2;
            color: #fff;
            padding-top: 100px;
        }
    </style>
</head>
<body>
    <div class="overlay"></div>
    <div class="content text-center">
        <h1>National Security Agency</h1>
        <p class="lead">Defending our nation. Securing the future.</p>
        <a href="{{ url_for('secure') }}" class="btn btn-primary">Employee Portal</a>
    </div>
</body>
</html>
''')

@app.route('/secure', methods=['GET', 'POST'])
def secure():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Simulate authentication process
        if username in users:
            expected_password = users[username]
            if password == expected_password:
                if username == 'admin':
                    return redirect(url_for('congratulations'))
                return render_template_string('''
                    <h1>Welcome, Agent {{ username }}!</h1>
                    <p>Your mission briefing is available in your inbox.</p>
                    <a href="{{ url_for('home') }}">Back to Home</a>
                ''', username=username)
            else:
                # Vulnerability: Exposing sensitive data in error message
                error_msg = f"Incorrect password for user '{username}'. Expected '{expected_password}'."
        else:
            error_msg = f"User '{username}' does not exist."
        return render_template_string('''
            <h1>Access Denied</h1>
            <p>{{ error_msg }}</p>
            <a href="{{ url_for('secure') }}">Try Again</a>
        ''', error_msg=error_msg)
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <title>NSA Employee Portal</title>
            <!-- Bootstrap CSS -->
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-dark text-white">
            <div class="container mt-5">
                <h1>Employee Secure Login</h1>
                <form method="post" class="mt-4">
                    <div class="mb-3">
                        <label>Username</label>
                        <input type="text" name="username" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label>Password</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
                <a href="{{ url_for('home') }}" class="btn btn-link text-white mt-3">Back to Home</a>
            </div>
        </body>
        </html>
    ''')

@app.route('/congratulations')
def congratulations():
    return render_template_string('''
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the sensitive data exposure vulnerability.</p>
        <p>Please report this finding to the security team immediately.</p>
        <a href="{{ url_for('home') }}">Back to Home</a>
    ''')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)