from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <!-- Include a modern CSS framework like Bootstrap -->
        <meta charset="UTF-8">
        <title>Global Bank - Welcome</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            /* Custom styles */
            body {
                background-color: #f0f2f5;
            }
            .navbar {
                margin-bottom: 20px;
            }
            .card {
                margin-top: 50px;
            }
            footer {
                margin-top: 50px;
                padding: 20px 0;
                background-color: #343a40;
                color: #fff;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <!-- Navigation Bar -->
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <a class="navbar-brand" href="#">Global Bank</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse"
                data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false"
                aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
        </nav>

        <!-- Main Content -->
        <div class="container">
            <div class="card">
                <div class="card-header">
                    <h3>Welcome to Global Bank</h3>
                </div>
                <div class="card-body">
                    <p>At Global Bank, your financial security is our top priority. Manage your accounts,
                    pay bills, and monitor your transactions all in one place.</p>
                    <form method="get" action="/search">
                        <div class="form-group">
                            <label for="query">Search Transactions</label>
                            <input type="text" class="form-control" id="query"
                                name="query" placeholder="Enter keyword or transaction ID">
                        </div>
                        <button type="submit" class="btn btn-primary">Search</button>
                    </form>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <footer>
            &copy; 2023 Global Bank. All rights reserved.
        </footer>

        <!-- Include Bootstrap JS -->
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script
            src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js">
        </script>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    query = request.args.get('query', '')
    # Intentional XSS vulnerability
    template = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Search Results</title>
        <link rel="stylesheet"
            href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body {
                background-color: #f0f2f5;
            }
            .card {
                margin-top: 50px;
            }
            footer {
                margin-top: 50px;
                padding: 20px 0;
                background-color: #343a40;
                color: #fff;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <!-- Main Content -->
        <div class="container">
            <div class="card">
                <div class="card-header">
                    <h3>Search Results for "{{ query | safe }}"</h3>
                </div>
                <div class="card-body">
                    <p>No transactions matched your search query.</p>
                    <a href="/" class="btn btn-secondary">Back to Home</a>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <footer>
            &copy; 2023 Global Bank. All rights reserved.
        </footer>

        <!-- Include Bootstrap JS -->
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script
            src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js">
        </script>

        <!-- Hidden congratulatory message -->
        <script>
            if (document.location.search.includes('congratulations')) {
                alert('Congratulations! You have found the hidden message.');
            }
        </script>
    </body>
    </html>
    '''
    return render_template_string(template, query=query)

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True, host='0.0.0.0', port=5000)