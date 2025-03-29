from flask import Flask, render_template_string, request, redirect, url_for
import base64

app = Flask(__name__)

@app.route('/')
def home():
    home_page = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Home - Excelsior Insurance</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    </head>
    <body>
        <div class="container mt-5">
            <div class="jumbotron">
                <h1 class="display-4">Welcome to Excelsior Insurance</h1>
                <p class="lead">We provide world-class insurance services tailored to your needs.</p>
                <hr class="my-4">
                <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a>.</p>
            </div>
        </div>
    </body>
    </html>
    '''
    return render_template_string(home_page)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    next_encoded = request.args.get('next')
    next_url = None
    if next_encoded:
        try:
            next_url = base64.urlsafe_b64decode(next_encoded.encode()).decode()
        except Exception as e:
            pass  # Ignore decoding errors
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # For the sake of example, accept any username/password
        # Get next_encoded from form data
        next_encoded = request.form.get('next')
        next_url = None
        if next_encoded:
            try:
                next_url = base64.urlsafe_b64decode(next_encoded.encode()).decode()
            except Exception as e:
                pass  # Ignore decoding errors
        if next_url:
            return redirect(next_url)
        else:
            return redirect(url_for('dashboard'))
    login_page = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Login - Excelsior Insurance</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    </head>
    <body>
        <div class="container mt-5">
            {% if error %}
            <div class="alert alert-danger" role="alert">
                {{ error }}
            </div>
            {% endif %}
            <h2>Login to Your Account</h2>
            <form method="post" action="">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" class="form-control" name="username" id="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" class="form-control" name="password" id="password" required>
                </div>
                {% if next_encoded %}
                <input type="hidden" name="next" value="{{ next_encoded }}">
                {% endif %}
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
        </div>
    </body>
    </html>
    '''
    return render_template_string(login_page, error=error, next_encoded=next_encoded)

@app.route('/dashboard')
def dashboard():
    dashboard_page = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Dashboard - Excelsior Insurance</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    </head>
    <body>
        <div class="container mt-5">
            <h2>Welcome to your Dashboard</h2>
            <p>Manage your policies and claims here.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(dashboard_page)

@app.route('/congratulations')
def congratulations():
    congrats_page = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Congratulations!</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    </head>
    <body>
        <div class="container mt-5">
            <h1>Congratulations!</h1>
            <p>You have successfully exploited the Unvalidated Redirects and Forwards vulnerability.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(congrats_page)
if __name__ == '__main__':
        app.run(debug=True)