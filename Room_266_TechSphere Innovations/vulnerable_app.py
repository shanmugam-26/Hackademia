from flask import Flask, render_template_string, request

app = Flask(__name__)

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TechSphere Innovations</title>
    <!-- Bootstrap CSS via CDN -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <!-- Custom CSS -->
    <style>
        .jumbotron {
            background-image: url('https://source.unsplash.com/1600x900/?technology');
            background-size: cover;
            color: white;
            text-shadow: 1px 1px 2px black;
        }
        .nav-link, .navbar-brand {
            color: white !important;
        }
        .footer {
            background-color: #333;
            color: white;
            padding: 20px;
        }
        .footer a {
            color: #ccc;
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
      <a class="navbar-brand" href="#">TechSphere</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"         aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" #navbarNav>
        <ul class="navbar-nav ml-auto">
          <li class="nav-item active">
            <a class="nav-link" href="#">Home </a>
          </li>
          <li class="nav-item">
           <a class="nav-link" href="#about">About Us</a>
          </li>
          <li class="nav-item">
           <a class="nav-link" href="#services">Services</a>
          </li>
          <li class="nav-item">
           <a class="nav-link" href="#contact">Contact</a>
          </li>
        </ul>
      </div>
    </nav>

    <!-- Jumbotron -->
    <div class="jumbotron text-center">
        <h1 class="display-4">Innovate. Integrate. Inspire.</h1>
        <p class="lead">Leading the way in technological advancements for a smarter future.</p>
    </div>

    <!-- Main Content -->
    <div class="container">
        <!-- About Us Section -->
        <section id="about" class="mt-5">
            <h2>About Us</h2>
            <p>At TechSphere Innovations, we are dedicated to delivering state-of-the-art technology solutions that empower businesses and individuals alike.</p>
        </section>

        <!-- Services Section -->
        <section id="services" class="mt-5">
            <h2>Our Services</h2>
            <ul>
                <li>Custom Software Development</li>
                <li>Cloud Integration</li>
                <li>Artificial Intelligence Solutions</li>
                <li>Data Analytics</li>
                <li>Cybersecurity</li>
            </ul>
        </section>

        <!-- Feedback Form -->
        <section id="feedback" class="mt-5">
            <h2>We Value Your Feedback</h2>
            <p>Please let us know your thoughts about our company and services.</p>
            <form method="post">
                <div class="form-group">
                    <label for="feedback">Your Feedback:</label>
                    <input type="text" class="form-control" id="feedback" name="feedback" placeholder="Enter your feedback">
                </div>
                <button type="submit" class="btn btn-primary">Submit</button>
            </form>
        </section>

        {% if feedback %}
            <section id="recent-feedback" class="mt-5">
                <h2>Recent Feedback</h2>
                <p>{{ feedback }}</p>
            </section>
            <script>
            // Check if an element with id 'congrats' exists in feedback
            if (document.querySelector('#recent-feedback #congrats')) {
                alert('Congratulations! You have successfully exploited the HTML Injection vulnerability.');
            }
            </script>
        {% endif %}

        <!-- Contact Section -->
        <section id="contact" class="mt-5 mb-5">
            <h2>Contact Us</h2>
            <p>Email: contact@techsphere.com</p>
            <p>Phone: (123) 456-7890</p>
        </section>
    </div>

    <!-- Footer -->
    <footer class="footer text-center">
        <p>&copy; 2023 TechSphere Innovations. All rights reserved.</p>
    </footer>

    <!-- Bootstrap and jQuery JS via CDN -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script     src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js"></script>
    <script     src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"></script>

</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        feedback = request.form.get('feedback', '')
        # Vulnerable to HTML Injection
        return render_template_string(HTML_TEMPLATE, feedback=feedback)
    else:
        return render_template_string(HTML_TEMPLATE, feedback='')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)