from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
<!doctype html>
<html lang="en">
<head>
    <title>TechNova Solutions</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        /* Custom styles */
    </style>
</head>
<body>
    <!-- Navigation bar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
      <a class="navbar-brand" href="#">TechNova Solutions</a>
    </nav>

    <!-- Hero section -->
    <div class="jumbotron jumbotron-fluid text-center bg-primary text-white py-5">
      <div class="container">
        <h1 class="display-4">Innovate the Future</h1>
        <p class="lead">We provide cutting-edge tech solutions for modern problems.</p>
      </div>
    </div>

    <!-- Content -->
    <div class="container my-5">
      <div class="row">
        <div class="col-md-6">
          <h2>About Us</h2>
          <p>At TechNova Solutions, we are committed to delivering innovative tech solutions that empower businesses worldwide.</p>
        </div>
        <div class="col-md-6">
          <h2>Our Services</h2>
          <p>We specialize in AI, cloud computing, and cybersecurity to keep your business ahead of the curve.</p>
        </div>
      </div>
    </div>

    <!-- Footer -->
    <footer class="bg-dark text-white text-center py-3">
      &copy; 2023 TechNova Solutions. All rights reserved.
    </footer>

    <!-- JavaScript to fetch sensitive data over insecure connection -->
    <script>
        // Insecure communication: Fetching sensitive data over HTTP
        fetch('http://localhost:5000/api/sensitive-data')
        .then(response => response.json())
        .then(data => {
            console.log('Data received:', data);
            // Use the sensitive data in some way
        })
        .catch(error => {
            console.error('Error fetching data:', error);
        });
    </script>
</body>
</html>
    ''')

@app.route('/api/sensitive-data')
def sensitive_data():
    data = {
        'secret_key': 'FLAG{congratulations_you_found_the_sensitive_data}'
    }
    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True)
