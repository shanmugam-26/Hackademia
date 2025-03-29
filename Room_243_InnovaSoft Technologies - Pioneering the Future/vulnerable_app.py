from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    user_input = ''
    if request.method == 'POST':
        user_input = request.form.get('user_input', '')
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>InnovaSoft Technologies - Pioneering the Future</title>
        <!-- Bootstrap CSS -->
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        <style>
            body {
                background-color: #f8f9fa;
            }
            .jumbotron {
                background-image: url('https://via.placeholder.com/1500x500');
                background-size: cover;
                color: white;
                text-shadow: 2px 2px #000;
            }
            .mission {
                background-color: #343a40;
                color: white;
                padding: 50px 0;
            }
            .mission h2 {
                margin-bottom: 30px;
            }
            .footer {
                background-color: #212529;
                color: #868e96;
                padding: 20px 0;
            }
        </style>
    </head>
    <body>
        <!-- Navbar -->
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
            <a class="navbar-brand" href="#">InnovaSoft</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" 
            aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse justify-content-end" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link active" href="#">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Solutions</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Careers</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Contact Us</a>
                    </li>
                </ul>
            </div>
        </nav>

        <!-- Jumbotron -->
        <div class="jumbotron text-center p-5">
            <h1 class="display-4">Welcome to InnovaSoft Technologies</h1>
            <p class="lead">Innovating the future, one line of code at a time.</p>
            <a href="#" class="btn btn-primary btn-lg">Discover More</a>
        </div>

        <!-- Mission Section -->
        <div class="mission text-center">
            <div class="container">
                <h2>Our Mission</h2>
                <p class="lead">To deliver cutting-edge software solutions that drive progress and innovation.</p>
            </div>
        </div>

        <!-- User Interaction Section -->
        <div class="container my-5">
            <h3 class="mb-4">Subscribe to our Newsletter</h3>
            <form method="POST" class="row g-3">
                <div class="col-md-6">
                    <label for="user_input" class="form-label">Enter your email or message:</label>
                    <input type="text" class="form-control" id="user_input" name="user_input" placeholder="Your email or message">
                </div>
                <div class="col-12">
                    <button type="submit" class="btn btn-success">Subscribe</button>
                </div>
            </form>
            {% if user_input %}
                <div class="alert alert-info mt-4" role="alert">
                    Thank you for your input: {{ user_input }}
                </div>
            {% endif %}
        </div>

        <!-- Footer -->
        <footer class="footer text-center">
            <div class="container">
                <span>&copy; 2023 InnovaSoft Technologies. All rights reserved.</span>
            </div>
        </footer>

        <!-- Bootstrap JS -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    '''
    # Vulnerable to HTML Injection: rendering 'user_input' without sanitization
    return render_template_string(template, user_input=user_input)
if __name__ == '__main__':
        app.run(debug=True)