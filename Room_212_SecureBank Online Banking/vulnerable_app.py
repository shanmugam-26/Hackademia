from flask import Flask, render_template_string, request
import os

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureBank Online Banking</title>
        <!-- Include Bootstrap CSS from CDN -->
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        <style>
            body {
                background-color: #f5f5f5;
            }
            .navbar {
                margin-bottom: 20px;
            }
            .jumbotron {
                background-image: url('https://source.unsplash.com/1600x900/?bank');
                background-size: cover;
                color: white;
                height: 300px;
                position: relative;
            }
            .jumbotron .container {
                position: absolute;
                bottom: 0;
            }
            .footer {
                background-color: #222;
                color: #bbb;
                padding: 20px 0;
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
          <a class="navbar-brand" href="#">SecureBank</a>
          <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
          </button>
        </nav>

        <div class="jumbotron">
            <div class="container">
                <h1 class="display-4">Welcome to SecureBank</h1>
                <p class="lead">Your trusted partner in financial success.</p>
            </div>
        </div>

        <div class="container">
            <h2>Latest News</h2>
            <p>We are pleased to announce the launch of our new online banking platform.</p>

            <h2>Contact Us</h2>
            <form action="/feedback" method="post">
              <div class="form-group">
                <label for="feedback">Your Feedback</label>
                <input type="text" class="form-control" id="feedback" name="feedback" placeholder="Enter your feedback">
              </div>
              <button type="submit" class="btn btn-primary">Submit</button>
            </form>
        </div>

        <footer class="footer">
          <div class="container text-center">
            <span>&copy; 2023 SecureBank. All rights reserved.</span>
          </div>
        </footer>

        <!-- Include Bootstrap JS from CDN -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''

@app.route('/feedback', methods=['POST'])
def feedback():
    feedback = request.form.get('feedback')
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Feedback Received - SecureBank</title>
        <!-- Include Bootstrap CSS from CDN -->
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head>
    <body>
        <div class="container">
            <h1>Thank you for your feedback!</h1>
            <p>Your feedback: {{ feedback }}</p>
            <a href="/" class="btn btn-primary">Return to Home</a>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, feedback=feedback)

@app.route('/congratulations')
def congratulations():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Congratulations!</title>
        <!-- Include Bootstrap CSS from CDN -->
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head>
    <body>
        <div class="container">
            <h1>Congratulations!</h1>
            <p>You have successfully exploited the SSTI vulnerability.</p>
        </div>
    </body>
    </html>
    '''
if __name__ == '__main__':
        app.run(debug=True)