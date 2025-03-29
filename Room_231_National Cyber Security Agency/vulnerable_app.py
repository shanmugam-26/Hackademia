from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>National Cyber Security Agency</title>
    <!-- Modern CSS Framework: Bootstrap -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-image: url('https://www.publicdomainpictures.net/pictures/320000/velka/background-image.png');
            background-size: cover;
        }
        .header-text {
            color: white;
            text-shadow: 2px 2px 4px #000000;
            margin-top: 100px;
        }
        .content-box {
            background-color: rgba(255, 255, 255, 0.8);
            padding: 30px;
            border-radius: 15px;
            margin-top: 50px;
        }
    </style>
</head>
<body>
    <div class="container text-center">
        <h1 class="header-text">National Cyber Security Agency</h1>
        <div class="content-box">
            <h2>Welcome to the NCSA Portal</h2>
            <p>Your security is our priority. Access restricted resources and manage national cybersecurity threats.</p>
            <a href="#" class="btn btn-primary btn-lg disabled">Employee Login</a>
            <a href="#" class="btn btn-secondary btn-lg disabled">Public Resources</a>
        </div>
    </div>
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
''')

# Vulnerable endpoint with improper access control
@app.route('/secure-admin-portal')
def admin_portal():
    # This endpoint is supposed to be protected but lacks proper access control
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard - National Cyber Security Agency</title>
    <!-- Modern CSS Framework: Bootstrap -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #343a40;
            color: white;
        }
        .congrats-box {
            margin-top: 150px;
        }
        .congrats-text {
            color: #28a745;
        }
    </style>
</head>
<body>
    <div class="container text-center congrats-box">
        <h1 class="congrats-text">Congratulations!</h1>
        <p>You have successfully exploited the improper access control vulnerability.</p>
        <p>This admin panel was accessed without proper authorization.</p>
    </div>
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
''')
if __name__ == '__main__':
        app.run(debug=True)