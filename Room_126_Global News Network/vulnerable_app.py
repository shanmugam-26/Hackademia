from flask import Flask, render_template_string, request, redirect, url_for, session
import os

app = Flask(__name__)
app.secret_key = 'super-secret-key'  # Misconfigured secret key

@app.route('/')
def home():
    return render_template_string(main_page_template)

# Admin login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    if request.method == 'POST':
        if request.form['username'] == 'admin' and request.form['password'] == 'admin':
            session['logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = 'Invalid Credentials'
    return render_template_string(admin_login_template, error=error)

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    else:
        return render_template_string(admin_dashboard_template)

# Read file route
@app.route('/read')
def read_file():
    filename = request.args.get('file', '')
    if filename:
        try:
            # Misconfiguration: Not checking for path traversal
            with open(filename, 'r') as f:
                return f.read(), 200, {'Content-Type': 'text/plain'}
        except Exception as e:
            return str(e), 500
    else:
        return 'No file specified', 400

# Main page template
main_page_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global News Network</title>
    <!-- Include Bootstrap CSS for styling -->
    <link rel="stylesheet"
          href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css"
          crossorigin="anonymous">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="#">Global News Network</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav mr-auto">
                <li class="nav-item active"><a class="nav-link" href="#">Home</a></li>
                <!-- Other nav items -->
            </ul>
        </div>
    </nav>
    <div class="container">
        <h1>Breaking News</h1>
        <p>Latest updates from around the globe...</p>
        <!-- Content -->
    </div>
    <!-- Hidden admin login link -->
    <div style="display:none;">
        <a href="/admin/login">Admin Login</a>
    </div>
    <!-- Hidden read function -->
    <script>
    // TODO: Remove before production
    // Debugging readFile function
    function readFile(filename) {
        fetch('/read?file=' + filename)
            .then(response => response.text())
            .then(data => console.log(data));
    }
    </script>
    <!-- Include Bootstrap JS and dependencies -->
    <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js"
            crossorigin="anonymous">
    </script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js"
            crossorigin="anonymous">
    </script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"
            crossorigin="anonymous">
    </script>
</body>
</html>
'''

# Admin login template
admin_login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Login - Global News Network</title>
    <!-- Include Bootstrap CSS for styling -->
    <link rel="stylesheet"
          href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css"
          crossorigin="anonymous">
</head>
<body>
    <div class="container">
        <h2>Admin Login</h2>
        {% if error %}
            <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <form method="post">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" class="form-control" name="username" id="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" class="form-control" name="password" id="password" required>
            </div>
            <!-- Remember Me Checkbox (Commented out, misconfigured) -->
            <!-- <div class="form-group form-check">
                <input type="checkbox" class="form-check-input" id="remember" name="remember" checked>
                <label class="form-check-label" for="remember">Remember Me</label>
            </div> -->
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
    <!-- Include Bootstrap JS and dependencies -->
    <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js"
            crossorigin="anonymous">
    </script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js"
            crossorigin="anonymous">
    </script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"
            crossorigin="anonymous">
    </script>
</body>
</html>
'''

# Admin dashboard template
admin_dashboard_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard - Global News Network</title>
    <!-- Include Bootstrap CSS for styling -->
    <link rel="stylesheet"
          href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css"
          crossorigin="anonymous">
</head>
<body>
    <div class="container">
        <h2>Welcome to the Admin Dashboard</h2>
        <p>You have successfully exploited the misconfiguration vulnerability! Congratulations!</p>
    </div>
    <!-- Include Bootstrap JS and dependencies -->
    <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js"
            crossorigin="anonymous">
    </script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js"
            crossorigin="anonymous">
    </script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"
            crossorigin="anonymous">
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True)