from flask import Flask, render_template_string, request, redirect, url_for, make_response

app = Flask(__name__)

index_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Elegance Fashion House</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="/">Elegance</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                {% if not authenticated %}
                <li class="nav-item">
                    <a class="nav-link" href="/login">Login</a>
                </li>
                {% else %}
                <li class="nav-item">
                    <a class="nav-link" href="/exclusive">Exclusive Collection</a>
                </li>
                {% endif %}
            </ul>
        </div>
    </nav>
    <div class="container">
        <h1>Welcome to Elegance Fashion House</h1>
        <p>Discover the latest trends in fashion.</p>
    </div>
</body>
</html>
"""

login_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - Elegance Fashion House</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h2>Login to access exclusive collections</h2>
        <form action="/login" method="post">
            <div class="form-group">
                <label for="username">Email address</label>
                <input type="email" class="form-control" id="username" name="username" placeholder="Enter email">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" class="form-control" id="password" name="password" placeholder="Password">
            </div>
            <br>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
</body>
</html>
"""

exclusive_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Exclusive Collection - Elegance Fashion House</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .congrats {{ display: none; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Exclusive Collection</h2>
        <p>Congratulations! You have accessed the exclusive collection.</p>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    auth = request.cookies.get('auth')
    authenticated = auth == '0'
    return render_template_string(index_html, authenticated=authenticated)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Vulnerable authentication logic
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            # Incorrectly checking credentials (Broken Authentication)
            if 'elegance.com' in username:
                resp = make_response(redirect(url_for('exclusive')))
                resp.set_cookie('auth', '0')  # Vulnerable cookie handling
                return resp
        return redirect(url_for('login'))
    else:
        return render_template_string(login_html)

@app.route('/exclusive')
def exclusive():
    auth = request.cookies.get('auth')
    if auth == '0':
        return render_template_string(exclusive_html)
    else:
        return redirect(url_for('login'))
if __name__ == '__main__':
        app.run(debug=True)