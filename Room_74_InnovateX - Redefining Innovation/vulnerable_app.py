from flask import Flask, render_template_string, request

app = Flask(__name__)

# HTML template with modern CSS framework and intentional HTML Injection vulnerability
template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>InnovateX - Redefining Innovation</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- Using Bootstrap 5 CSS Framework -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* Custom Styles */
        body {
            background-color: #f8f9fa;
        }
        .hero-section {
            background-image: url('https://source.unsplash.com/1600x900/?technology,innovation');
            background-size: cover;
            background-position: center;
            color: white;
            padding: 100px 0;
        }
        .hero-section h1 {
            font-size: 4rem;
            font-weight: bold;
        }
        .content-section {
            padding: 60px 0;
        }
        .footer {
            background-color: #212529;
            color: #6c757d;
            padding: 20px 0;
            text-align: center;
        }
    </style>
</head>
<body>

    <!-- Navigation Bar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
      <div class="container-fluid">
        <a class="navbar-brand" href="#">InnovateX</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"         aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
      </div>
    </nav>

    <!-- Hero Section -->
    <div class="hero-section text-center">
        <div class="container">
            <h1>Welcome to InnovateX</h1>
            <p class="lead">Empowering the next generation of innovators.</p>
            <a href="#join-us" class="btn btn-primary btn-lg mt-4">Join Us Today</a>
        </div>
    </div>

    <!-- Content Section -->
    <div class="content-section">
        <div class="container">
            <h2 class="text-center mb-5">Our Vision</h2>
            <p>At InnovateX, we are committed to fostering innovation through cutting-edge technology solutions that transform industries and improve lives. Our team of experts works tirelessly to bring you the best in class services that exceed expectations.</p>
            <hr>
            <h3 class="mt-5" id="join-us">Get in Touch</h3>
            <p>We'd love to hear from you! Please fill out the form below to share your thoughts.</p>
            <!-- Feedback Form -->
            <form method="GET" action="/">
                <div class="mb-3">
                    <label for="feedback" class="form-label">Your Feedback:</label>
                    <input type="text" class="form-control" id="feedback" name="feedback" placeholder="Enter your feedback here">
                </div>
                <button type="submit" class="btn btn-success">Submit Feedback</button>
            </form>
            {% if feedback %}
            <!-- Intentional HTML Injection Vulnerability -->
            <div class="mt-4">
                <h5>Your Feedback:</h5>
                {{ feedback | safe }}
            </div>
            {% endif %}
        </div>
    </div>

    <!-- Footer -->
    <div class="footer">
        <p>&copy; 2023 InnovateX Inc. All rights reserved.</p>
    </div>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"></script>

    {% if 'congrats' in feedback|lower %}
    <script>
        alert('Congratulations! You have successfully exploited the vulnerability.');
    </script>
    {% endif %}

</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    feedback = request.args.get('feedback', '')
    # Intentionally render the feedback without sanitization to allow HTML Injection
    return render_template_string(template, feedback=feedback)
if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True, host='0.0.0.0', port=5000)