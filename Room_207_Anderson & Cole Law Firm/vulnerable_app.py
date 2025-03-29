from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    search = request.args.get('search', '')
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Anderson & Cole Law Firm</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <style>
            body {
                padding-top: 60px;
            }
            .footer {
                position: fixed;
                bottom: 0;
                width: 100%;
                height: 60px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 960px;
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
            <div class="container-fluid">
                <a class="navbar-brand" href="#">Anderson & Cole</a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarCollapse">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarCollapse">
                    <form class="d-flex" method="get">
                        <input class="form-control me-2" type="search" name="search" placeholder="Search" aria-label="Search">
                        <button class="btn btn-outline-success" type="submit">Search</button>
                    </form>
                </div>
            </div>
        </nav>

        <main class="container">
            <div class="bg-light p-5 rounded">
                <h1>Welcome to Anderson & Cole Law Firm</h1>
                <p class="lead">Providing expert legal services since 1990.</p>
                <p>{{ search | safe }}</p>
            </div>
        </main>

        <footer class="footer">
            <div class="container">
                <span class="text-muted">&copy; 2023 Anderson & Cole Law Firm</span>
            </div>
        </footer>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''
    return render_template_string(template)

@app.route('/congratulations')
def congratulations():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Congratulations!</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head>
    <body>
        <div class="container text-center" style="padding-top: 100px;">
            <h1>Congratulations!</h1>
            <p>You have successfully exploited the vulnerability.</p>
        </div>
    </body>
    </html>
    '''
if __name__ == '__main__':
        app.jinja_env.autoescape = False
        app.run(debug=True)