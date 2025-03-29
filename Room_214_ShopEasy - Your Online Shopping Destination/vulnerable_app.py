from flask import Flask, render_template_string, request
app = Flask(__name__)

# The main page
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        search = request.form.get('search', '')
        # Intentionally render the search input without sanitization to introduce XSS vulnerability
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>ShopEasy - Your Online Shopping Destination</title>
                <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/css/bootstrap.min.css">
            </head>
            <body>
                <nav class="navbar navbar-expand-lg navbar-light bg-light">
                  <a class="navbar-brand" href="#">ShopEasy</a>
                  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
                    <span class="navbar-toggler-icon"></span>
                  </button>
                  <div class="collapse navbar-collapse" id="navbarNav">
                    <form class="form-inline ml-auto" method="post">
                      <input class="form-control mr-sm-2" type="search" placeholder="Search" name="search" value="{{ search | safe }}">
                      <button class="btn btn-outline-success my-2 my-sm-0" type="submit">Search</button>
                    </form>
                  </div>
                </nav>
                <div class="container mt-5">
                  <h3>Search Results for "{{ search  | safe }}"</h3>
                  <p>No products found matching your search.</p>
                </div>
            </body>
            </html>
        ''', search=search)
    return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>ShopEasy - Your Online Shopping Destination</title>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/css/bootstrap.min.css">
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-light bg-light">
              <a class="navbar-brand" href="#">ShopEasy</a>
              <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
              </button>
              <div class="collapse navbar-collapse" id="navbarNav">
                <form class="form-inline ml-auto" method="post">
                  <input class="form-control mr-sm-2" type="search" placeholder="Search" name="search">
                  <button class="btn btn-outline-success my-2 my-sm-0" type="submit">Search</button>
                </form>
              </div>
            </nav>
            <div class="container mt-5">
                <h1>Welcome to ShopEasy!</h1>
                <p>Your one-stop shop for all your needs.</p>
                <div class="row">
                  <div class="col-md-4">
                    <div class="card">
                      <img src="https://via.placeholder.com/150" class="card-img-top" alt="Product 1">
                      <div class="card-body">
                        <h5 class="card-title">Product 1</h5>
                        <p class="card-text">$19.99</p>
                        <a href="#" class="btn btn-primary">Buy Now</a>
                      </div>
                    </div>
                  </div>
                  <div class="col-md-4">
                    <div class="card">
                      <img src="https://via.placeholder.com/150" class="card-img-top" alt="Product 2">
                      <div class="card-body">
                        <h5 class="card-title">Product 2</h5>
                        <p class="card-text">$29.99</p>
                        <a href="#" class="btn btn-primary">Buy Now</a>
                      </div>
                    </div>
                  </div>
                  <div class="col-md-4">
                    <div class="card">
                      <img src="https://via.placeholder.com/150" class="card-img-top" alt="Product 3">
                      <div class="card-body">
                        <h5 class="card-title">Product 3</h5>
                        <p class="card-text">$39.99</p>
                        <a href="#" class="btn btn-primary">Buy Now</a>
                      </div>
                    </div>
                  </div>
                </div>
            </div>
            <footer class="bg-light text-center text-lg-start mt-5">
              <div class="text-center p-3">
                © 2023 ShopEasy Inc.
              </div>
            </footer>
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
            <script>
              if(document.location.hash.includes('xss_exploited')) {
                alert('Congratulations! You have exploited the XSS vulnerability!');
              }
            </script>
        </body>
        </html>
    '''
if __name__ == '__main__':
      app.jinja_env.autoescape = False
      app.run(debug=True)