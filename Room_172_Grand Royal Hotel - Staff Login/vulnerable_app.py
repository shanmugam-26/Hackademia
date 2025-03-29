from flask import Flask, render_template_string, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'supersecretkey'

login_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grand Royal Hotel - Staff Login</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-image: url('https://images.unsplash.com/photo-1603052871113-1c89f4dd46d1');
            background-size: cover;
            color: white;
        }
        .login-form {
            margin-top: 100px;
            background-color: rgba(0,0,0,0.7);
            padding: 30px;
            border-radius: 10px;
        }
        .login-form h2 {
            color: #ffc107;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-4 login-form">
            <h2 class="text-center">Staff Login</h2>
            <form action="{{ url_for('login') }}" method="post" class="mt-4">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" class="form-control" name="username" id="username" required placeholder="Enter username">
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" class="form-control" name="password" id="password" required placeholder="Enter password">
                </div>
                {% with messages = get_flashed_messages() %}
                  {% if messages %}
                    <div class="alert alert-danger" role="alert">
                      {{ messages[0] }}
                    </div>
                  {% endif %}
                {% endwith %}
                <button type="submit" class="btn btn-warning btn-block">Login</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>
"""

admin_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grand Royal Hotel - Admin Panel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .admin-panel {
            margin-top: 50px;
        }
        .congrats {
            margin-top: 20px;
            color: green;
        }
    </style>
</head>
<body>
<div class="container admin-panel">
    <h1 class="text-center">Welcome to the Admin Panel</h1>
    <p class="text-center">Manage reservations, customer data, and hotel settings here.</p>
    <p class="text-center congrats">Congratulations! You've successfully bypassed the authentication.</p>
</div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Vulnerable authentication logic
        if username == 'admin' or password == 'admin123':
            return render_template_string(admin_page)
        else:
            flash('Invalid credentials. Please try again.')
            return redirect(url_for('login'))

    return render_template_string(login_page)
if __name__ == '__main__':
        app.run(debug=True, port=5000)