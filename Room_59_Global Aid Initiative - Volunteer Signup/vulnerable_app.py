from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        volunteer_name = request.form.get('volunteer_name', '')
        # Intentionally vulnerable code: render the volunteer name directly into the page without sanitization
        template = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Global Aid Initiative - Volunteer Signup</title>
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
            <style>
            body {{
                background-color: #f8f9fa;
            }}
            .thank-you {{
                margin-top: 50px;
                text-align: center;
            }}
            </style>
        </head>
        <body>
            <div class="container thank-you">
            <h1>Thank You for Signing Up, {{ volunteer_name|safe }}!</h1>
            <p class="lead">We appreciate your willingness to help us make a difference.</p>
            <p>If you have any questions, please contact us at <a href="mailto:contact@globalaidinitiative.org">contact@globalaidinitiative.org</a>.</p>
            </div>
        </body>
        </html>
        '''.format(volunteer_name=volunteer_name)
        # Add a hidden congratulations message if the vulnerability is exploited
        if "<script>" in volunteer_name.lower():
            template += '''
            <!-- Congratulations! You have successfully exploited the HTML Injection vulnerability. -->
            '''
        return render_template_string(template)
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Aid Initiative</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
        <style>
            .jumbotron {{
                background-image: url('https://via.placeholder.com/1500x500');
                background-size: cover;
                color: white;
                text-shadow: 2px 2px 4px #000000;
            }}
            .content {{
                margin-top: 30px;
            }}
            footer {{
                background-color: #343a40;
                color: white;
                padding: 20px 0;
                position: fixed;
                width: 100%;
                bottom: 0;
            }}
        </style>
    </head>
    <body>

    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <a class="navbar-brand" href="/">Global Aid Initiative</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item"><a class="nav-link" href="/about">About Us</a></li>
                <li class="nav-item"><a class="nav-link" href="/programs">Programs</a></li>
                <li class="nav-item"><a class="nav-link" href="/get-involved">Get Involved</a></li>
                <li class="nav-item"><a class="nav-link" href="/contact">Contact</a></li>
            </ul>
        </div>
    </nav>

    <div class="jumbotron text-center">
        <h1 class="display-4">Empowering Communities Globally</h1>
        <p class="lead">Join us in our mission to create sustainable solutions and improve lives worldwide.</p>
        <a href="#signup" class="btn btn-primary btn-lg">Volunteer Today</a>
    </div>

    <div class="container content">
        <h2 id="about">About Global Aid Initiative</h2>
        <p>Global Aid Initiative is a nonprofit organization committed to addressing the most pressing needs of communities around the world. We focus on sustainable development, education, healthcare, and disaster relief.</p>

        <h2 id="signup" class="mt-5">Volunteer Signup</h2>
        <p>Become a part of our global family and help us make a lasting impact.</p>
        <form method="post" action="/" class="mb-5">
            <div class="form-group">
                <label for="volunteer_name">Name:</label>
                <input type="text" class="form-control" id="volunteer_name" name="volunteer_name" required>
            </div>
            <button type="submit" class="btn btn-success">Sign Up</button>
        </form>
    </div>

    <footer class="text-center">
        <div class="container">
            <p>© 2023 Global Aid Initiative. All rights reserved.</p>
            <p>
                <a href="/privacy" class="text-white">Privacy Policy</a> |
                <a href="/terms" class="text-white">Terms of Service</a>
            </p>
        </div>
    </footer>

    </body>
    </html>
    '''

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)