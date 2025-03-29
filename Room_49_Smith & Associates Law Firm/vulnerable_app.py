from flask import Flask, render_template_string, request
import re

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Smith & Associates Law Firm</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body { padding-top: 50px; }
            .jumbotron { background-color: #f7f7f7; }
            .navbar { background-color: #2c3e50 !important; }
            .navbar-brand, .nav-link, .navbar-nav .nav-link { color: #ecf0f1 !important; }
        </style>
    </head>
    <body>
        <nav class="navbar fixed-top navbar-expand-lg navbar-dark">
            <a class="navbar-brand" href="#">Smith & Associates</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav mr-auto">
                    <li class="nav-item"><a class="nav-link" href="#">About Us</a></li>
                    <li class="nav-item"><a class="nav-link" href="#">Practice Areas</a></li>
                    <li class="nav-item"><a class="nav-link" href="#">Attorneys</a></li>
                    <li class="nav-item"><a class="nav-link" href="#">Contact</a></li>
                </ul>
                <form class="form-inline my-2 my-lg-0" action="/search">
                    <input class="form-control mr-sm-2" type="search" placeholder="Search" name="q">
                    <button class="btn btn-outline-light my-2 my-sm-0" type="submit">Search</button>
                </form>
            </div>
        </nav>
        <div class="container">
            <div class="jumbotron text-center">
                <h1>Welcome to Smith & Associates</h1>
                <p>Your trusted partner in legal excellence.</p>
                <a class="btn btn-primary btn-lg" href="#" role="button">Learn more</a>
            </div>
            <div class="row">
                <div class="col-md-4">
                    <h2>Expertise</h2>
                    <p>We specialize in corporate law, family law, and criminal defense.</p>
                </div>
                <div class="col-md-4">
                    <h2>Experience</h2>
                    <p>Over 25 years of providing top-notch legal services.</p>
                </div>
                <div class="col-md-4">
                    <h2>Integrity</h2>
                    <p>Committed to upholding the highest ethical standards.</p>
                </div>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    q = request.args.get('q', '')
    secret = 'Congratulations! You have exploited the SSTI vulnerability.'
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Results - Smith & Associates Law Firm</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body { padding-top: 50px; }
            .navbar { background-color: #2c3e50 !important; }
            .navbar-brand, .nav-link, .navbar-nav .nav-link { color: #ecf0f1 !important; }
            .container { margin-top: 30px; }
        </style>
    </head>
    <body>
        <nav class="navbar fixed-top navbar-expand-lg navbar-dark">
            <a class="navbar-brand" href="#">Smith & Associates</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNavSearch">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNavSearch">
                <ul class="navbar-nav mr-auto">
                    <li class="nav-item"><a class="nav-link" href="#">About Us</a></li>
                    <li class="nav-item"><a class="nav-link" href="#">Practice Areas</a></li>
                    <li class="nav-item"><a class="nav-link" href="#">Attorneys</a></li>
                    <li class="nav-item"><a class="nav-link" href="#">Contact</a></li>
                </ul>
                <form class="form-inline my-2 my-lg-0" action="/search">
                    <input class="form-control mr-sm-2" type="search" placeholder="Search" name="q">
                    <button class="btn btn-outline-light my-2 my-sm-0" type="submit">Search</button>
                </form>
            </div>
        </nav>
        <div class="container">
            <h2>Search Results for "{{ q }}"</h2>
            <p>No results found for "{{ q }}". Please try a different keyword.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, q=q)
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)