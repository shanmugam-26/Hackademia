from flask import Flask, render_template_string, request
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    search_query = ''
    if request.method == 'POST':
        search_query = request.form.get('search', '')
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Travels Agency</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    </head>
    <body>
    <!-- Navigation Bar -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">Global Travels Agency</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav"
          aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav mr-auto">
              <li class="nav-item active">
                  <a class="nav-link" href="#">Home <span class="sr-only">(current)</span></a>
              </li>
              <li class="nav-item">
                  <a class="nav-link" href="#">Destinations</a>
              </li>
              <li class="nav-item">
                  <a class="nav-link" href="#">Tours</a>
              </li>
              <li class="nav-item">
                  <a class="nav-link" href="#">Contact Us</a>
              </li>
          </ul>
          <form class="form-inline my-2 my-lg-0" method="POST">
              <input class="form-control mr-sm-2" type="search" placeholder="Search Destinations" aria-label="Search" name="search">
              <button class="btn btn-outline-success my-2 my-sm-0" type="submit">Search</button>
          </form>
      </div>
    </nav>
    <!-- Main Content -->
    <div class="container">
        {% if search_query %}
            <h2>Search Results for "{{ search_query|safe }}"</h2>
            <p>No results found for "{{ search_query|safe }}". Please try again.</p>
        {% else %}
            <div class="jumbotron mt-4">
                <h1 class="display-4">Explore the World with Us!</h1>
                <p class="lead">Discover amazing places at exclusive deals.</p>
                <hr class="my-4">
                <p>Get ready for an unforgettable journey.</p>
                <a class="btn btn-primary btn-lg" href="#" role="button">Learn more</a>
            </div>
        {% endif %}
    </div>
    <!-- Footer -->
    <footer class="footer bg-light text-center">
      <div class="container">
          <span class="text-muted">© 2023 Global Travels Agency. All rights reserved.</span>
      </div>
    </footer>
    <!-- Scripts -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''
    # Intentionally render the template without escaping (using |safe filter) to introduce XSS vulnerability
    return render_template_string(template, search_query=search_query)
if __name__ == '__main__':
        app.jinja_env.autoescape = False
        app.run(debug=True, host='0.0.0.0', port=5000)