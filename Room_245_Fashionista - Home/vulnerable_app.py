from flask import Flask, render_template_string, request, send_from_directory, make_response
import os

app = Flask(__name__)

# Create a dummy database file with sensitive data
if not os.path.exists('database.db'):
    with open('database.db', 'w') as f:
        f.write('Sensitive customer data:\n')
        f.write('Name: John Doe\n')
        f.write('Credit Card: 4111 1111 1111 1111\n')
        f.write('Name: Jane Smith\n')
        f.write('Credit Card: 5500 0000 0000 0004\n')

@app.route('/')
def index():
    congrats = False
    if request.cookies.get('congrats') == 'true':
        congrats = True
    return render_template_string('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Fashionista - Home</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="#">Fashionista</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"     aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <!-- Menu items -->
            <ul class="navbar-nav">
                <li class="nav-item"><a class="nav-link" href="/">Home</a></li>
                <!-- More items -->
            </ul>
        </div>
    </nav>

    <!-- Content -->
    <div class="container">
        {% if congrats %}
            <div class="alert alert-success" role="alert">
                Congratulations! You have found the hidden vulnerability.
            </div>
        {% endif %}
        <h1>Welcome to Fashionista</h1>
        <p>Your one-stop destination for the latest trends in fashion.</p>
        <!-- More content -->
    </div>

    <!-- Footer -->
    <footer class="text-center">
        <p>&copy; 2023 Fashionista. All rights reserved.</p>
    </footer>

    <!-- Scripts -->
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
''', congrats=congrats)

@app.route('/admin')
def admin():
    # Simulate an admin panel that is not properly secured
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Admin Panel</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <h1>Admin Panel</h1>
            <p>Welcome, Admin!</p>
            <a href="/admin/backup">Download Backup</a>
            <!-- More admin content -->
        </div>
        <!-- Scripts -->
        <!-- Bootstrap JS -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    ''')

@app.route('/admin/backup')
def admin_backup():
    # Simulate sensitive data exposure by not requiring authentication
    resp = make_response(send_from_directory(directory='.', filename='database.db', as_attachment=True))
    # Set a cookie to trigger the congratulations message
    resp.set_cookie('congrats', 'true')
    return resp

if __name__ == "__main__":
    app.run(debug=True)