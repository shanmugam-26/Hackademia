from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Adventures Travel Agency</title>
        <!-- Include Bootstrap CSS from CDN -->
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body {
                background-image: url('https://images.unsplash.com/photo-1507525428034-b723cf961d3e');
                background-size: cover;
                color: #fff;
            }
            .container {
                margin-top: 50px;
                background: rgba(0, 0, 0, 0.6);
                padding: 20px;
                border-radius: 10px;
            }
            h1, h2, p {
                text-align: center;
            }
            .navbar {
                margin-bottom: 20px;
            }
            .footer {
                margin-top: 50px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <!-- Navigation Bar -->
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
            <a class="navbar-brand" href="#">Global Adventures</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" 
                aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
        </nav>
        <!-- Main Content -->
        <div class="container">
            <h1>Welcome to Global Adventures</h1>
            <p>Discover your next destination with us!</p>
            <!-- Search form -->
            <form action="/search" method="get">
                <div class="form-group">
                    <label for="destination"><h3>Search for destinations:</h3></label>
                    <input type="text" class="form-control" id="destination" name="destination" placeholder="Enter destination">
                </div>
                <button type="submit" class="btn btn-primary btn-lg btn-block">Search</button>
            </form>
        </div>
        <!-- Footer -->
        <div class="footer">
            <p>&copy; 2023 Global Adventures Travel Agency</p>
        </div>
        <!-- Include Bootstrap JS and dependencies -->
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    destination = request.args.get('destination', '')
    # Vulnerable to HTML Injection
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Results for {}</title>
        <!-- Include Bootstrap CSS from CDN -->
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body {
                background-image: url('https://images.unsplash.com/photo-1513836279014-a89f7a76ae86');
                background-size: cover;
                color: #fff;
            }
            .container {
                margin-top: 50px;
                background: rgba(0, 0, 0, 0.6);
                padding: 20px;
                border-radius: 10px;
            }
            h1, h2, p {
                text-align: center;
            }
            .card {
                margin: 20px;
                background: rgba(255, 255, 255, 0.1);
            }
            .footer {
                margin-top: 50px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <!-- Navigation Bar -->
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
            <a class="navbar-brand" href="/">Global Adventures</a>
        </nav>
        <!-- Main Content -->
        <div class="container">
            <h1>Search Results for {}</h1>
            <p>We have found the following destinations based on your search:</p>
            <!-- Example of search results -->
            <div class="row">
                <div class="col-md-4">
                    <div class="card">
                        <img src="https://images.unsplash.com/photo-1507525428034-b723cf961d3e" class="card-img-top" alt="Beach">
                        <div class="card-body">
                            <h5 class="card-title">Tropical Paradise</h5>
                            <p class="card-text">Experience the ultimate relaxation on pristine beaches.</p>
                            <a href="#" class="btn btn-primary">View Trip</a>
                        </div>
                    </div>
                </div>
                <!-- More cards can be added here -->
            </div>
        </div>
        <!-- Footer -->
        <div class="footer">
            <p>&copy; 2023 Global Adventures Travel Agency</p>
        </div>
        <!-- Include Bootstrap JS and dependencies -->
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    </body>
    </html>
    '''.format(destination, destination)
if __name__ == '__main__':
        app.run(debug=True)