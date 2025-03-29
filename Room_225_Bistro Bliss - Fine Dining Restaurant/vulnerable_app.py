from flask import Flask, request, render_template_string

app = Flask(__name__)

# Home page
@app.route('/')
def index():
    return render_template_string(''''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Bistro Bliss - Fine Dining Restaurant</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .jumbotron {
            background-image: url('https://source.unsplash.com/1600x900/?fine-dining');
            background-size: cover;
            color: white;
            text-shadow: 2px 2px #000;
        }
        .nav-link {
            color: white !important;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <a class="navbar-brand" href="/">Bistro Bliss</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"          aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
           <ul class="navbar-nav">
               <li class="nav-item active">
                   <a class="nav-link" href="/">Home</a>
               </li>
               <li class="nav-item">
                   <a class="nav-link" href="/menu">Menu</a>
               </li>
               <li class="nav-item">
                   <a class="nav-link" href="/reservations">Reservations</a>
               </li>
               <li class="nav-item">
                   <a class="nav-link" href="/contact">Contact</a>
               </li>
           </ul>
        </div>
    </nav>

    <div class="jumbotron jumbotron-fluid text-center">
        <div class="container">
            <h1 class="display-4">Welcome to Bistro Bliss</h1>
            <p class="lead">Experience the elegance of fine dining.</p>
            <form action="/search" method="get" class="form-inline justify-content-center">
                <input type="text" name="q" class="form-control mr-sm-2" placeholder="Search our menu">
                <button type="submit" class="btn btn-primary my-2 my-sm-0">Search</button>
            </form>
        </div>
    </div>

    <div class="container">
        <h2>Our Signature Dishes</h2>
        <div class="row">
            <!-- Sample dishes -->
            <div class="col-md-4">
                <img src="https://source.unsplash.com/400x300/?food" class="img-fluid" alt="Dish">
                <h3>Truffle Risotto</h3>
                <p>A creamy risotto with truffles and parmesan.</p>
            </div>
            <div class="col-md-4">
                <img src="https://source.unsplash.com/400x300/?cuisine" class="img-fluid" alt="Dish">
                <h3>Seared Salmon</h3>
                <p>Fresh Atlantic salmon seared to perfection.</p>
            </div>
            <div class="col-md-4">
                <img src="https://source.unsplash.com/400x300/?gourmet" class="img-fluid" alt="Dish">
                <h3>Chocolate Lava Cake</h3>
                <p>A rich and warm chocolate dessert.</p>
            </div>
        </div>
    </div>

    <footer class="bg-dark text-white text-center p-3 mt-4">
        &copy; 2023 Bistro Bliss | <a href="/privacy" class="text-white">Privacy Policy</a>
    </footer>

    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
</body>
</html>
''')

# Search page with XSS vulnerability
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Search Results - Bistro Bliss</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <a class="navbar-brand" href="/">Bistro Bliss</a>
        <!-- Navbar content -->
    </nav>

    <div class="container">
        <h1 class="mt-5">Search Results</h1>
        <p class="lead">You searched for: <b>{{ query }}</b></p>
        <div id="results"></div>
        <a href="/" class="btn btn-secondary">Back to Home</a>
    </div>

    <footer class="bg-dark text-white text-center p-3 mt-4">
        &copy; 2023 Bistro Bliss
    </footer>

    <script>
        var searchTerm = "{{ query | safe }}";
        // Simulate processing
        var resultsDiv = document.getElementById("results");
        if (searchTerm.length > 0) {
            resultsDiv.innerHTML = "No results found for \"" + searchTerm + "\"";
        } else {
            resultsDiv.innerHTML = "Please enter a search term.";
        }
    </script>
</body>
</html>
''', query=query)
if __name__ == '__main__':
        app.run(debug=True)