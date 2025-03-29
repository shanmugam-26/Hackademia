from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SafeBank Online</title>
        <!-- Include Bootstrap CSS from CDN -->
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
        <!-- Some custom styling -->
        <style>
            body { padding-top: 50px; }
            .login-form { max-width: 500px; margin: 0 auto; }
            .container { text-align: center; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to SafeBank Online Banking</h1>
            <p>Please <a href="{{ url_for('login') }}">login</a> to access your account.</p>
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # For the purpose of this example, the valid credentials are 'user' and 'pass'
        if username == 'user' and password == 'pass':
            return redirect(url_for('dashboard'))
        else:
            # Vulnerability: Expose sensitive data in error message
            error = f'Invalid credentials. You entered username: {username} and password: {password}'
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SafeBank Login</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
        <style>
            .login-form { max-width: 400px; margin: 0 auto; }
            body { padding-top: 50px; }
        </style>
    </head>
    <body>
        <div class="login-form">
            <h2>Login to SafeBank</h2>
            {% if error %}
                <div class="alert alert-danger">{{ error }}</div>
            {% endif %}
            <form method="post">
                <div class="form-group">
                    <label for="username">Account Number</label>
                    <input type="text" name="username" class="form-control" id="username" placeholder="Enter account number">
                </div>
                <div class="form-group">
                    <label for="password">PIN</label>
                    <input type="password" name="password" class="form-control" id="password" placeholder="Enter PIN">
                </div>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
        </div>
    </body>
    </html>
    ''', error=error)

@app.route('/dashboard')
def dashboard():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SafeBank Dashboard</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
        <style>
            .container { margin-top: 50px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Welcome to your SafeBank Account</h2>
            <p>Your balance is: $10,000</p>
            <h3>Congratulations!</h3>
            <p>You have successfully exploited the Sensitive Data Exposure vulnerability.</p>
        </div>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)