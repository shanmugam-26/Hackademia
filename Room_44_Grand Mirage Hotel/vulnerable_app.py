from flask import Flask, request, render_template_string

app = Flask(__name__)

# Template for the main page
template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grand Mirage Hotel</title>
    <!-- Include Bootstrap CSS from CDN -->
    <link rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
          integrity="sha384-YoVtvCD65fGt4o/Xs9lJnK5B1UIGhQEVmpumpYD99+ZGKZwhsZ25Vf6ZvNUR+1E6"
          crossorigin="anonymous">
    <style>
        /* Additional custom styles */
        body {
            background-color: #f8f9fa;
        }
        .hero {
            background-image: url('https://images.unsplash.com/photo-1512917774080-9991f1c4c750');
            background-size: cover;
            background-position: center;
            height: 400px;
            position: relative;
        }
        .hero-text {
            position: absolute;
            bottom: 30px;
            left: 30px;
            color: white;
        }
        .overlay {
            position: absolute;
            top: 0;
            left: 0;
            height: 400px;
            width: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        .nav-link {
            color: #fff !important;
        }
    </style>
</head>
<body>
<!-- Navigation Bar -->
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">Grand Mirage Hotel</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"       aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
      <span class="navbar-toggler-icon"></span>
    </button>
  </div>
</nav>

<!-- Hero Section -->
<div class="hero">
    <div class="overlay"></div>
    <div class="hero-text">
        <h1>Welcome to the Grand Mirage Hotel</h1>
        <p>Experience luxury like never before.</p>
    </div>
</div>

<!-- Main Content -->
<div class="container mt-5">
    <h2>Book Your Stay</h2>
    <form method="get" action="/">
        <div class="row g-3">
            <div class="col-md-4">
                <label for="checkin" class="form-label">Check-In Date</label>
                <input type="date" class="form-control" id="checkin" name="checkin">
            </div>
            <div class="col-md-4">
                <label for="checkout" class="form-label">Check-Out Date</label>
                <input type="date" class="form-control" id="checkout" name="checkout">
            </div>
            <div class="col-md-4">
                <label for="guests" class="form-label">Guests</label>
                <input type="number" class="form-control" id="guests" name="guests" min="1" max="10">
            </div>
        </div>
        <div class="mt-3">
            <label for="query" class="form-label">Special Requests</label>
            <input type="text" class="form-control" id="query" name="query" placeholder="e.g., Sea view, extra pillows">
        </div>
        <button type="submit" class="btn btn-primary mt-3">Search Availability</button>
    </form>
    {% if query %}
    <div class="alert alert-info mt-4" role="alert">
        <!-- Vulnerable code: reflecting user input without proper escaping -->
        <p>Searching availability with special requests: {{ query| safe}}</p>
    </div>
    {% endif %}
</div>

<!-- Footer -->
<footer class="bg-dark text-white mt-5 p-4 text-center">
    © 2023 Grand Mirage Hotel. All rights reserved.
</footer>

<!-- Bootstrap JS and dependencies -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js" integrity="sha384-Qx6BQjU844VY9T2WOFdeZkmUMgVqLA8pSMgj9njr2Ggm5F6lnsjaXGiIl7m73ElJ" crossorigin="anonymous"></script>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    query = request.args.get('query')
    checkin = request.args.get('checkin')
    checkout = request.args.get('checkout')
    guests = request.args.get('guests')
    if query:
        # Vulnerable: Not sanitizing user input
        pass  # No sanitization is purposely applied here
    return render_template_string(template, query=query)
if __name__ == '__main__':
        app.jinja_env.autoescape = False
        app.run(debug=True, host='0.0.0.0', port=5000)