from flask import Flask, render_template_string, request, jsonify
import os

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['FLAG'] = 'Congratulations, you have found the secret message!'

index_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Acme Consulting</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* Custom styles */
        body { padding-top: 60px; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light fixed-top">
        <a class="navbar-brand" href="/">Acme Consulting</a>
        <!-- Navbar content -->
    </nav>
    <div class="container">
        <h1 class="mt-5">Welcome to Acme Consulting</h1>
        <p>Your trusted partner in business solutions.</p>
        <!-- Content -->
        <p>At Acme Consulting, we specialize in delivering innovative solutions tailored to your business needs. Our team of experts is committed to driving success and value.</p>
        <p>Contact us today to learn how we can help transform your business.</p>
    </div>
    <footer class="footer mt-auto py-3 bg-light fixed-bottom">
        <div class="container">
            <span class="text-muted">© 2023 Acme Consulting</span>
        </div>
    </footer>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(index_template)

@app.route('/debug')
def debug():
    # This route should be disabled in production, but due to misconfiguration, it's accessible.
    return jsonify({key: str(value) for key, value in app.config.items()})

if __name__ == "__main__":
        app.run(debug=True)