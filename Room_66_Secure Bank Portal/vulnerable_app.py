from flask import Flask, render_template_string, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 's3cr3t'

# Sample users data
users = {
    'user1': {'password': 'pass1', 'balance': '$10,000'},
    'user2': {'password': 'pass2', 'balance': '$5,000'},
}

# Template using modern CSS frameworks (e.g., Bootstrap)
template = '''
<!doctype html>
<html lang="en">
<head>
    <title>Secure Bank Portal</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-5">
    {% if not session.get('user') %}
    <div class="row">
        <div class="col-md-4 offset-md-4">
            <h2 class="text-center">Welcome to Secure Bank</h2>
            <form method="POST" action="/login">
                <div class="mb-3">
                    <label for="username" class="form-label">User ID</label>
                    <input type="text" class="form-control" id="username" name="username" placeholder="Enter your User ID">
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Passcode</label>
                    <input type="password" class="form-control" id="password" name="password" placeholder="Enter your Passcode">
                </div>
                <button type="submit" class="btn btn-primary w-100">Access Account</button>
            </form>
        </div>
    </div>
    {% else %}
    <div class="row">
        <div class="col-md-6 offset-md-3">
            <h2 class="text-center">Account Summary for {{ session.get('user') }}</h2>
            <p class="text-center">Current Balance: {{ users[session.get('user')]['balance'] }}</p>
            <div class="text-center">
                <a href="/logout" class="btn btn-secondary">Logout</a>
            </div>
        </div>
    </div>
    {% endif %}
</div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return render_template_string(template, users=users)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    # Improper access control vulnerability
    if username in users and password == users[username]['password']:
        session['user'] = username
    else:
        # Vulnerability: Improperly redirects authenticated users without proper checks
        session['user'] = request.form.get('username')  # Improperly sets session without verification
    return redirect(url_for('index'))

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

# Congratulations route (hidden)
@app.route('/congrats', methods=['GET'])
def congrats():
    if session.get('congrats'):
        return "Congratulations! You've exploited the vulnerability."
    else:
        return redirect(url_for('index'))
if __name__ == '__main__':
            app.run(debug=True, port=5000)