from flask import Flask, request, render_template_string

app = Flask(__name__)

# HTML Templates
main_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Wanderlust Travels</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="/">Wanderlust Travels</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link" href="/destinations">Destinations</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/tours">Tours</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/login">Member Login</a>
                </li>
            </ul>
        </div>
    </nav>
    <div class="container">
        <div class="jumbotron mt-4">
            <h1 class="display-4">Explore the World with Wanderlust Travels!</h1>
            <p class="lead">Your adventure begins here. Discover breathtaking destinations and unique experiences.</p>
            <hr class="my-4">
            <p>Join our members-only platform for exclusive deals and packages.</p>
            <a class="btn btn-primary btn-lg" href="/login" role="button">Login</a>
        </div>
    </div>
</body>
</html>
'''

login_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Member Login - Wanderlust Travels</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h2 class="mt-5">Member Login</h2>
        <form action="/login" method="POST" class="mt-4">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" placeholder="Enter username">
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" placeholder="Enter password">
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
</body>
</html>
'''

secret_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Exclusive Offers - Wanderlust Travels</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script>
        // For internal use only
        var secretToken = "{{ token }}";
    </script>
</head>
<body>
    <div class="container">
        <h2 class="mt-5">Exclusive Member Offers</h2>
        <p>Welcome, esteemed member! Enjoy our curated travel packages just for you.</p>
    </div>
</body>
</html>
'''

congrats_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <div class="alert alert-success mt-5" role="alert">
            <h4 class="alert-heading">Congratulations!</h4>
            <p>You have successfully exploited the vulnerability.</p>
            <hr>
            <p class="mb-0">This demonstrates the importance of secure communication in web applications.</p>
        </div>
    </div>
</body>
</html>
'''

# Routes
@app.route('/')
def index():
    return render_template_string(main_page)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Insecure communication of credentials over HTTP
        username = request.form.get('username')
        password = request.form.get('password')
        # Check credentials (for demo purposes, any credentials are accepted)
        if username and password:
            # Normally, token should be securely generated and stored
            # Here, it's exposed via client-side script (vulnerability)
            token = 's3cr3t_t0k3n'
            return render_template_string(secret_page, token=token)
        else:
            return "Invalid credentials", 401
    else:
        return render_template_string(login_page)

@app.route('/congrats')
def congrats():
    return render_template_string(congrats_page)

# Simulate an insecure API endpoint that accepts token via GET parameter
@app.route('/api/data')
def api_data():
    token = request.args.get('token')
    if token == 's3cr3t_t0k3n':
        # User exploited the vulnerability by obtaining the token
        return {'message': 'Congratulations! You found the secret data.'}
    else:
        return {'error': 'Invalid token'}, 403
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)