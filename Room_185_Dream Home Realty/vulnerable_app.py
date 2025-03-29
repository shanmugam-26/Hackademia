from flask import Flask, render_template_string, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Templates
index_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>Dream Home Realty</title>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="/">Dream Home Realty</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"        aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link" href="/listings">Listings</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/contact">Contact Us</a>
                </li>
                <!-- Agent Login link is not visible -->
            </ul>
        </div>
    </nav>

    <div class="container mt-5">
        <h1>Welcome to Dream Home Realty</h1>
        <p>Your dream home awaits...</p>
        <!-- Content -->
    </div>
</body>
</html>
'''

listings_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>Property Listings - Dream Home Realty</title>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <!-- Navbar content same as above -->
        <a class="navbar-brand" href="/">Dream Home Realty</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"        aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link" href="/listings">Listings</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/contact">Contact Us</a>
                </li>
                <!-- Agent Login link is hidden -->
            </ul>
        </div>
    </nav>

    <div class="container mt-5">
        <h1>Property Listings</h1>
        <!-- Some property listings -->
        <div class="row">
            <!-- Property 1 -->
            <div class="col-md-4">
                <div class="card">
                    <img src="https://via.placeholder.com/300x200" class="card-img-top" alt="Property 1">
                    <div class="card-body">
                        <h5 class="card-title">Luxurious Villa</h5>
                        <p class="card-text">$1,200,000</p>
                    </div>
                </div>
            </div>
            <!-- Property 2 -->
            <div class="col-md-4">
                <div class="card">
                    <img src="https://via.placeholder.com/300x200" class="card-img-top" alt="Property 2">
                    <div class="card-body">
                        <h5 class="card-title">Modern Apartment</h5>
                        <p class="card-text">$850,000</p>
                    </div>
                </div>
            </div>
            <!-- Property 3 -->
            <div class="col-md-4">
                <div class="card">
                    <img src="https://via.placeholder.com/300x200" class="card-img-top" alt="Property 3">
                    <div class="card-body">
                        <h5 class="card-title">Cozy Cottage</h5>
                        <p class="card-text">$600,000</p>
                    </div>
                </div>
            </div>
            <!-- More properties -->
        </div>
    </div>
</body>
</html>
'''

contact_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <title>Contact Us - Dream Home Realty</title>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <!-- Same navbar -->
        <a class="navbar-brand" href="/">Dream Home Realty</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"        aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link" href="/listings">Listings</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/contact">Contact Us</a>
                </li>
                <!-- Agent Login link is hidden -->
            </ul>
        </div>
    </nav>

    <div class="container mt-5">
        <h1>Contact Us</h1>
        <p>Please fill out the form below to get in touch.</p>
        <!-- Contact form -->
        <form method="post" action="/contact">
            <div class="mb-3">
                <label class="form-label">Name</label>
                <input type="text" class="form-control" name="name">
            </div>
            <div class="mb-3">
                <label class="form-label">Email</label>
                <input type="email" class="form-control" name="email">
            </div>
            <div class="mb-3">
                <label class="form-label">Message</label>
                <textarea class="form-control" name="message"></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
    </div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

    <title>Agent Login - Dream Home Realty</title>
</head>
<body>
    <div class="container mt-5">
        <h1>Agent Login</h1>
        <form method="post" action="/login">
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input type="text" class="form-control" name="username">
            </div>
            <!-- Hidden form field that can be manipulated -->
            <div class="mb-3" style="display:none;">
                <input type="hidden" name="is_admin" value="false">
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input type="password" class="form-control" name="password">
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
</body>
</html>
'''

agent_portal_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

    <title>Agent Portal - Dream Home Realty</title>
</head>
<body>
    <div class="container mt-5">
        <h1>Agent Portal</h1>
        <p>Welcome, Agent {{ username }}.</p>
        <p>Here are the confidential listings:</p>
        <!-- Confidential data -->
        <ul>
            <li>Top Secret Property: Hidden Mansion, $5,000,000</li>
            <li>Exclusive Listing: Private Island, $20,000,000</li>
        </ul>

        <!-- Congratulations prompt -->
        {% if is_admin %}
        <div class="alert alert-success" role="alert">
            Congratulations! You have successfully accessed the Admin features.
        </div>
        {% endif %}
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(index_template)

@app.route('/listings')
def listings():
    return render_template_string(listings_template)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Handle form submission
        # (In a real application, process the data)
        return redirect(url_for('index'))
    return render_template_string(contact_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = request.form.get('is_admin', 'false') == 'true'
        # Improper Access Control: Trusting client-side hidden field
        # No proper authentication is implemented
        session['logged_in'] = True
        session['username'] = username
        session['is_admin'] = is_admin
        return redirect(url_for('agent_portal'))
    return render_template_string(login_template)

@app.route('/agent')
def agent_portal():
    if session.get('logged_in'):
        return render_template_string(agent_portal_template, username=session.get('username'), is_admin=session.get('is_admin'))
    else:
        return redirect(url_for('login'))
if __name__ == '__main__':
        app.run(debug=True)