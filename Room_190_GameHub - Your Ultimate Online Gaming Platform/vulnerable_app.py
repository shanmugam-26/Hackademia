from flask import Flask, render_template_string, request

app = Flask(__name__)

# HTML template with Bootstrap included
template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <title>GameHub - Your Ultimate Online Gaming Platform</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- Bootstrap CSS CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #1a1a1a;
            color: #e2e2e2;
        }
        .navbar-brand, .nav-link {
            color: #e2e2e2 !important;
        }
        .game-card {
            background-color: #2a2a2a;
            border: none;
        }
        .game-card img {
            height: 200px;
            object-fit: cover;
        }
        .footer {
            background-color: #0d0d0d;
            color: #666;
            padding: 20px 0;
            margin-top: 40px;
        }
        .search-result {
            margin-top: 20px;
        }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">GameHub</a>
    <form class="d-flex" method="GET" action="/">
      <input class="form-control me-2" type="search" placeholder="Search Games" aria-label="Search" name="search">
      <button class="btn btn-outline-success" type="submit">Search</button>
    </form>
  </div>
</nav>

<div class="container mt-5">

    {% if search_query %}
    <h2>Search Results for "{{ search_query | safe }}"</h2>
    <!-- Vulnerable output -->
    <div class="search-result">{{ search_query | safe }}</div>
    {% else %}
    <h1 class="text-center">Welcome to GameHub</h1>
    <p class="text-center">Discover and play your favorite games online!</p>

    <div class="row">
        <div class="col-md-4">
            <div class="card game-card">
                <img src="https://via.placeholder.com/300x200.png?text=Game+1" class="card-img-top" alt="Game 1">
                <div class="card-body">
                    <h5 class="card-title">Adventure Quest</h5>
                    <p class="card-text">Embark on an epic journey through mystical lands.</p>
                    <a href="#" class="btn btn-primary">Play Now</a>
                </div>
            </div>
        </div>
        <!-- Repeat game cards for other games -->
        <div class="col-md-4">
            <div class="card game-card">
                <img src="https://via.placeholder.com/300x200.png?text=Game+2" class="card-img-top" alt="Game 2">
                <div class="card-body">
                    <h5 class="card-title">Space Invaders</h5>
                    <p class="card-text">Defend Earth from an alien invasion.</p>
                    <a href="#" class="btn btn-primary">Play Now</a>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card game-card">
                <img src="https://via.placeholder.com/300x200.png?text=Game+3" class="card-img-top" alt="Game 3">
                <div class="card-body">
                    <h5 class="card-title">Puzzle Mania</h5>
                    <p class="card-text">Challenge your mind with intricate puzzles.</p>
                    <a href="#" class="btn btn-primary">Play Now</a>
                </div>
            </div>
        </div>
    </div>
    {% endif %}

    <!-- Hidden Congratulations Message -->
    {% if 'congrats' in request.args %}
    <div class="alert alert-success mt-4" role="alert">
      Congratulations! You have successfully exploited the vulnerability.
    </div>
    {% endif %}

</div>

<footer class="footer text-center">
    <div class="container">
        <p>&copy; 2023 GameHub. All rights reserved.</p>
    </div>
</footer>

<!-- Bootstrap JS CDN -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    search_query = request.args.get('search', '')
    return render_template_string(template, search_query=search_query, request=request)
if __name__ == '__main__':
        app.jinja_env.autoescape = False
        app.run(debug=True, port=5000)