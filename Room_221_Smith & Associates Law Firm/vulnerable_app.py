from flask import Flask, render_template_string, send_file, abort
import os

app = Flask(__name__)

# Simulated sensitive data (e.g., database credentials)
DATABASE_URL = 'mysql://admin:SuperSecretPassword123@localhost/lawfirmdb'

@app.route('/')
def index():
    html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Smith & Associates Law Firm</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
        <!-- Our custom CSS -->
        <style>
            body {
                background-color: #f5f5f5;
            }
            .navbar {
                margin-bottom: 20px;
            }
            .jumbotron {
                background-image: url('https://images.unsplash.com/photo-1521791136064-7986c2920216');
                background-size: cover;
                color: white;
                height: 500px;
                position: relative;
            }
            .jumbotron .container {
                position: relative;
                top: 50%;
                transform: translateY(-50%);
            }
            .footer {
                background-color: #222;
                color: #fff;
                padding: 20px 0;
                text-align: center;
            }
        </style>
    <!--
    Note: Remember to remove backup files before deploying to production!
    Backup files are located at /static/backup/config.bak containing sensitive information.

    TODO: Remove the following line before deployment
    DATABASE_BACKUP_PATH = '/static/backup/config.bak'
    -->
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
          <a class="navbar-brand" href="#">Smith & Associates</a>
          <button class="navbar-toggler" type="button" data-toggle="collapse" 
                  data-target="#navbarNav" aria-controls="navbarNav" 
                  aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
          </button>
          <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ms-auto">
              <li class="nav-item active">
                <a class="nav-link" href="#">Home<span class="sr-only"></span></a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="#">Our Firm</a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="#">Practice Areas</a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="#">Attorneys</a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="#">Contact Us</a>
              </li>
            </ul>
          </div>
        </nav>

        <div class="jumbotron">
          <div class="container">
            <h1 class="display-4">Experienced Legal Representation</h1>
            <p class="lead">Dedicated to providing quality legal services to our clients.</p>
            <a href="#" class="btn btn-primary btn-lg">Learn More</a>
          </div>
        </div>

        <div class="container mb-5">
          <div class="row">
            <div class="col-md-4">
              <h2>Our Firm</h2>
              <p>At Smith & Associates, we pride ourselves on delivering top-notch legal services with a personal touch. Our team of experienced attorneys is here to guide you through your legal challenges.</p>
              <a href="#" class="btn btn-secondary">Read More</a>
            </div>
            <div class="col-md-4">
              <h2>Practice Areas</h2>
              <p>We specialize in corporate law, real estate, intellectual property, and family law. Our diverse expertise allows us to provide comprehensive legal solutions.</p>
              <a href="#" class="btn btn-secondary">Discover More</a>
            </div>
            <div class="col-md-4">
              <h2>Contact Us</h2>
              <p>Have questions? We're here to help. Get in touch with us to schedule a consultation with one of our attorneys.</p>
              <a href="#" class="btn btn-secondary">Get in Touch</a>
            </div>
          </div>
        </div>

        <footer class="footer">
          <div class="container">
            <p>&copy; 2023 Smith & Associates Law Firm. All rights reserved.</p>
          </div>
        </footer>

        <!-- Optional JavaScript -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''
    return render_template_string(html)

# Exposed backup file
@app.route('/static/backup/config.bak')
def backup():
    # Simulated sensitive data exposure
    content = '''
    # Configuration Backup File
    DATABASE_URL = '{}'
    SECRET_KEY = 'SuperSecretKey456'
    ADMIN_PASSWORD = 'AdminPass789'
    '''.format(DATABASE_URL)
    return content, {'Content-Type': 'text/plain'}

@app.route('/congratulations')
def congratulations():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Congratulations</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container text-center mt-5">
            <h1 class="display-4 text-success">Congratulations!</h1>
            <p class="lead">You have successfully exploited the sensitive data exposure vulnerability.</p>
            <p>Thank you for helping us improve our security measures.</p>
        </div>
    </body>
    </html>
    ''')
if __name__ == '__main__':
        app.run(debug=True)