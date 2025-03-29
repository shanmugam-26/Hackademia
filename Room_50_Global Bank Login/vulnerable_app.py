from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

secret_flag = "Congratulations! You have successfully exploited the SSTI vulnerability."

users = {
    'admin': 'password123'
}

@app.route('/', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username in users and users[username] == password:
            return redirect(url_for('dashboard', user=username))
        else:
            error = 'Invalid username or password. Please try again.'
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Global Bank Login</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body {
                background-color: #f8f9fa;
            }
            .login-form {
                width: 340px;
                margin: 50px auto;
            }
            .login-form form {
                margin-bottom: 15px;
                background: #fff;
                box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);
                padding: 30px;
            }
            .login-form .btn {
                font-size: 16px;
                font-weight: bold;
            }
        </style>
    </head>
    <body>
        <div class="login-form">
            <form method="post">
                <h2 class="text-center">Member Login</h2>
                {% if error %}
                <div class="alert alert-danger" role="alert">
                    {{ error }}
                </div>
                {% endif %}
                <div class="form-group">
                    <input type="text" class="form-control" name="username" placeholder="Username" required="required">
                </div>
                <div class="form-group">
                    <input type="password" class="form-control" name="password" placeholder="Password" required="required">
                </div>
                <div class="form-group">
                    <button type="submit" class="btn btn-primary btn-block">Log in</button>
                </div>
                <div class="clearfix">
                    <a href="{{ url_for('guest') }}" class="float-right">Continue as Guest</a>
                </div>
            </form>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, error=error)

@app.route('/guest', methods=['GET', 'POST'])
def guest():
    query = ''
    result = ''
    if request.method == 'POST':
        query = request.form.get('query', '')
        result = render_template_string("No results found for '{{ query }}'.", query=query, secret_flag=secret_flag)
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Global Bank Guest Dashboard</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body {
                background-color: #f8f9fa;
            }
            .container {
                margin-top: 50px;
            }
            .footer {
                position: fixed;
                bottom: 0;
                width: 100%;
                height: 60px;
                line-height: 60px;
                background-color: #f5f5f5;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Welcome, Guest!</h2>
            <p>You can search for bank branches below:</p>
            <form method="post">
                <div class="form-group">
                    <input type="text" class="form-control" name="query" placeholder="Enter search query">
                </div>
                <button type="submit" class="btn btn-primary">Search</button>
            </form>
            {% if result %}
            <hr>
            <p>{{ result|safe }}</p>
            {% endif %}
        </div>
        <footer class="footer">
            <div class="container">
                <span class="text-muted">© 2023 Global Bank</span>
            </div>
        </footer>
    </body>
    </html>
    '''
    return render_template_string(template, result=result)

@app.route('/dashboard')
def dashboard():
    user = request.args.get('user', 'User')
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Global Bank Dashboard</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body {{
                background-color: #f8f9fa;
            }}
            .container {{
                margin-top: 50px;
            }}
            .footer {{
                position: fixed;
                bottom: 0;
                width: 100%;
                height: 60px;
                line-height: 60px;
                background-color: #f5f5f5;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Welcome, {{ user }}!</h2>
            <p>Your account overview is not available at this time.</p>
        </div>
        <footer class="footer">
            <div class="container">
                <span class="text-muted">© 2023 Global Bank</span>
            </div>
        </footer>
    </body>
    </html>
    '''
    return render_template_string(template, user=user)
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)