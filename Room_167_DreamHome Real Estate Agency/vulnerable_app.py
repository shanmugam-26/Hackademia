from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route('/')
def index():
    html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>DreamHome Real Estate Agency</title>
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {
                padding-top: 56px;
            }
            .property-card {
                margin-bottom: 30px;
            }
            .navbar {
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-light bg-white fixed-top">
            <div class="container">
                <a class="navbar-brand" href="#">DreamHome</a>
                <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
            </div>
        </nav>
        <div class="container">
            <h1 class="mt-5">Find Your Dream Home</h1>
            <p class="lead">Explore our exclusive listings.</p>
            <div class="row">
                <div class="col-md-4 property-card">
                    <div class="card">
                        <img src="https://via.placeholder.com/350x150" class="card-img-top" alt="Property 1">
                        <div class="card-body">
                            <h5 class="card-title">Elegant Family House</h5>
                            <p class="card-text">$500,000 - 4 Bed, 3 Bath</p>
                            <a href="/property?id=1" class="btn btn-primary">View Details</a>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 property-card">
                    <div class="card">
                        <img src="https://via.placeholder.com/350x150" class="card-img-top" alt="Property 2">
                        <div class="card-body">
                            <h5 class="card-title">Modern Apartment</h5>
                            <p class="card-text">$350,000 - 2 Bed, 2 Bath</p>
                            <a href="/property?id=2" class="btn btn-primary">View Details</a>
                        </div>
                    </div>
                </div>
                <div class="col-md-4 property-card">
                    <div class="card">
                        <img src="https://via.placeholder.com/350x150" class="card-img-top" alt="Property 3">
                        <div class="card-body">
                            <h5 class="card-title">Country Cottage</h5>
                            <p class="card-text">$250,000 - 3 Bed, 2 Bath</p>
                            <a href="/property?id=3" class="btn btn-primary">View Details</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <!-- Bootstrap JS (Optional) -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route('/property')
def property():
    prop_id = request.args.get('id', '1')
    # Vulnerable to Directory Traversal
    file_path = 'properties/{}.html'.format(prop_id)
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return render_template_string(content)
    except FileNotFoundError:
        return render_template_string('<h1>Property not found.</h1>'), 404

@app.route('/congratulations')
def congratulations():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Congratulations!</title>
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container text-center">
            <h1 class="mt-5">Congratulations!</h1>
            <p class="lead">You have successfully exploited the directory traversal vulnerability.</p>
        </div>
    </body>
    </html>
    ''')
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)