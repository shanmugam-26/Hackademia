from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Department of Cyber Defense</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
        <style>
            body {
                background-color: #f5f5f5;
            }
            .navbar {
                margin-bottom: 20px;
            }
            .header {
                background: url('https://www.example.com/agency-banner.jpg') no-repeat center center;
                background-size: cover;
                height: 300px;
                color: white;
                text-align: center;
                padding-top: 120px;
            }
            .header h1 {
                font-size: 50px;
                text-shadow: 2px 2px #000;
            }
            .content {
                padding: 20px;
            }
            .footer {
                background-color: #343a40;
                color: white;
                padding: 10px 0;
                text-align: center;
                position: fixed;
                width: 100%;
                bottom: 0;
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
            <a class="navbar-brand" href="#">DCD</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" 
                aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
	    <div class="collapse navbar-collapse" id="navbarNav">
	        <ul class="navbar-nav">
	            <li class="nav-item active">
	                <a class="nav-link" href="/">Home</a>
	            </li>
	            <li class="nav-item">
	                <a class="nav-link" href="/about">About Us</a>
	            </li>
	            <li class="nav-item">
	                <a class="nav-link" href="/contact">Contact</a>
	            </li>
	        </ul>
	    </div>
        </nav>
        <div class="header">
            <h1>Department of Cyber Defense</h1>
            <p>Protecting the Nation's Digital Infrastructure</p>
        </div>
        <div class="content container">
            <h2>Welcome to the Department of Cyber Defense</h2>
            <p>
                Our mission is to safeguard the nation's digital assets against emerging cyber threats. We collaborate 
                with private and public sectors to enhance cybersecurity resilience.
            </p>
            <form action="/search" method="get" class="form-inline my-4">
                <input type="text" name="query" class="form-control mr-sm-2" placeholder="Search our site">
                <button type="submit" class="btn btn-outline-primary">Search</button>
            </form>
        </div>
        <div class="footer">
            &copy; 2023 Department of Cyber Defense. All rights reserved.
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
	    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    query = request.args.get('query', '')
    # Intentionally vulnerable to HTML Injection
    html_content = render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Results - DCD</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
        <style>
            .content {
                padding: 20px;
            }
            .footer {
                background-color: #343a40;
                color: white;
                padding: 10px 0;
                text-align: center;
                position: fixed;
                width: 100%;
                bottom: 0;
            }
        </style>
    </head>
    <body>
        <div class="content container">
            <h2>Search Results for: {{ query }}</h2>
            <p>No matching results found.</p>
            <a href="/">Return to Home</a>
        </div>
        <div class="footer">
            &copy; 2023 Department of Cyber Defense. All rights reserved.
        </div>
    </body>
    </html>
    ''', query=query)
    return html_content

@app.route('/congratulations')
def congratulations():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Congratulations!</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
        <style>
            body {
                background-color: #28a745;
                color: white;
                text-align: center;
                padding-top: 50px;
            }
            h1 {
                font-size: 60px;
                margin-bottom: 40px;
            }
            p {
                font-size: 24px;
            }
            .btn-home {
                margin-top: 30px;
            }
        </style>
    </head>
    <body>
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the HTML Injection vulnerability.</p>
        <a href="/" class="btn btn-light btn-home">Return to Home</a>
    </body>
    </html>
    '''
if __name__ == '__main__':
        app.jinja_env.autoescape = False
        app.run(debug=True, host='0.0.0.0', port=5000)