from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

home_page_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SwiftTrans - Your Trusted Transportation Partner</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/5.0.0/css/bootstrap.min.css">
</head>
<body>
    <!-- Navigation bar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
      <a class="navbar-brand" href="/">SwiftTrans</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav"     aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
  <div class="collapse navbar-collapse" id="navbarNav">
    <ul class="navbar-nav">
      <!-- other nav items -->
      <li class="nav-item">
        <a class="nav-link" href="/book">Book a Ride</a>
      </li>
    </ul>
  </div>
</nav>

<!-- Main content -->
<div class="container">
    <div class="jumbotron mt-4">
        <h1 class="display-4">Welcome to SwiftTrans!</h1>
        <p class="lead">We provide fast and reliable transportation services across the country.</p>
        <hr class="my-4">
        <p>Experience the comfort and safety of our modern fleet.</p>
        <a class="btn btn-primary btn-lg" href="/book" role="button">Book Now</a>
    </div>
</div>

</body>
</html>
'''

booking_page_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SwiftTrans - Book a Ride</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/5.0.0/css/bootstrap.min.css">
</head>
<body>
    <!-- Navigation bar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
      <a class="navbar-brand" href="/">SwiftTrans</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav"     aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
  <div class="collapse navbar-collapse" id="navbarNav">
    <ul class="navbar-nav">
      <!-- other nav items -->
      <li class="nav-item">
        <a class="nav-link active" href="/book">Book a Ride</a>
      </li>
    </ul>
  </div>
</nav>

<!-- Main content -->
<div class="container">
    <h2 class="mt-4">Book a Ride</h2>
    <form action="/api/booking" method="GET">
        <div class="form-group">
            <label for="fullname">Full Name</label>
            <input type="text" class="form-control" id="fullname" name="fullname" placeholder="Enter your full name">
        </div>
        <div class="form-group">
            <label for="pickup">Pickup Location</label>
            <input type="text" class="form-control" id="pickup" name="pickup" placeholder="Enter pickup location">
        </div>
        <div class="form-group">
            <label for="dropoff">Dropoff Location</label>
            <input type="text" class="form-control" id="dropoff" name="dropoff" placeholder="Enter dropoff location">
        </div>
        <!-- Hidden field containing a secret code -->
        <input type="hidden" name="secret_code" value="SWIFT2023SECRET">
        <button type="submit" class="btn btn-primary mt-3">Submit</button>
    </form>
</div>

</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page_template)

@app.route('/book')
def book():
    return render_template_string(booking_page_template)

@app.route('/api/booking', methods=['GET'])
def api_booking():
    fullname = request.args.get('fullname')
    pickup = request.args.get('pickup')
    dropoff = request.args.get('dropoff')
    secret_code = request.args.get('secret_code')
    # Process booking (we won't store it for now)

    # Return a confirmation page
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>SwiftTrans - Booking Confirmation</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/5.0.0/css/bootstrap.min.css">
    </head>
    <body>
        <div class="container">
            <h2 class="mt-4">Booking Confirmation</h2>
            <p>Thank you, {{ fullname }}. Your ride from {{ pickup }} to {{ dropoff }} has been booked.</p>
            <a href="/" class="btn btn-primary">Go back to Home</a>
        </div>
    </body>
    </html>
    ''', fullname=fullname, pickup=pickup, dropoff=dropoff)

@app.route('/congratulations', methods=['GET'])
def congratulations():
    code = request.args.get('code')
    if code == 'SWIFT2023SECRET':
        return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Congratulations!</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/5.0.0/css/bootstrap.min.css">
        </head>
        <body>
            <div class="container">
                <h2 class="mt-4">Congratulations!</h2>
                <p>You have successfully exploited the vulnerability.</p>
            </div>
        </body>
        </html>
        ''')
    else:
        return redirect(url_for('home'))
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)