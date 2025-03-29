from flask import Flask, request, render_template_string

app = Flask(__name__)

# Secret flag for users who exploit the SSTI vulnerability
FLAG = "Congratulations! You've successfully exploited the SSTI vulnerability."

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>LearnHub University</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
            <a class="navbar-brand" href="#">LearnHub University</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav mr-auto">
                    <li class="nav-item"><a class="nav-link" href="/">Home</a></li>
                    <li class="nav-item"><a class="nav-link" href="/courses">Courses</a></li>
                    <li class="nav-item"><a class="nav-link" href="/contact">Contact Us</a></li>
                </ul>
                <span class="navbar-text">
                    Empowering Minds, Shaping Futures
                </span>
            </div>
        </nav>
        <div class="jumbotron">
            <div class="container mt-5">
                <h1 class="display-4">Welcome to LearnHub University</h1>
                <p class="lead">Your portal to a world of knowledge.</p>
                <hr class="my-4">
                <p>Join us to embark on an unforgettable educational journey.</p>
                <a class="btn btn-primary btn-lg" href="/apply" role="button">Apply Now</a>
            </div>
        </div>
        <div class="container">
            <h2>Latest News</h2>
            <p>Stay tuned for the latest updates from our campus.</p>
        </div>
        <div class="container mt-5">
            <h2>We Value Your Feedback</h2>
            <form method="POST" action="/feedback">
                <div class="mb-3">
                    <label for="feedback" class="form-label">Leave your feedback:</label>
                    <input type="text" class="form-control" id="feedback" name="message" placeholder="Your feedback">
                </div>
                <button type="submit" class="btn btn-primary">Submit Feedback</button>
            </form>
        </div>
        <footer class="footer mt-auto py-3 bg-light">
            <div class="container">
                <span class="text-muted">© 2023 LearnHub University.</span>
            </div>
        </footer>
    </body>
    </html>
    '''

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        message = request.form.get('message', '')
        template = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>Thank You - LearnHub University</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        </head>
        <body>
            <div class="container mt-5">
                <h1>Thank You!</h1>
                <p>Your feedback: ''' + message + '''</p>
            </div>
            <footer class="footer mt-auto py-3 bg-light">
                <div class="container">
                    <span class="text-muted">© 2023 LearnHub University.</span>
                </div>
            </footer>
        </body>
        </html>
        '''
        return render_template_string(template, FLAG=FLAG)
    else:
        return '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>Error - LearnHub University</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        </head>
        <body>
            <div class="container mt-5">
                <h1>Error</h1>
                <p>Feedback not received.</p>
            </div>
            <footer class="footer mt-auto py-3 bg-light">
                <div class="container">
                    <span class="text-muted">© 2023 LearnHub University.</span>
                </div>
            </footer>
        </body>
        </html>
        '''
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)