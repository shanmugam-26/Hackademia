from flask import Flask, render_template_string, request
import lxml.etree

app = Flask(__name__)

# Create the secret file
with open('secret.txt', 'w') as f:
    f.write('Congratulations, you have found the secret!')

home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Luxury Stay Hotel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        .hero {
            background-image: url('https://source.unsplash.com/1600x900/?hotel,luxury');
            background-size: cover;
            background-position: center;
            height: 60vh;
            position: relative;
            color: white;
        }
        .hero-text {
            position: absolute;
            bottom: 20px;
            left: 20px;
        }
        .hero-text h1 {
            font-size: 4em;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="/">Luxury Stay Hotel</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"           aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
         </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
                <li class="nav-item">
                    <a class="nav-link" href="/booking">Book Now</a>
                </li>
            </ul>
        </div>
    </nav>
    <div class="hero">
        <div class="hero-text">
            <h1>Experience Luxury</h1>
            <p>Where comfort meets elegance.</p>
            <a href="/booking" class="btn btn-primary btn-lg">Book Your Stay</a>
        </div>
    </div>
    <div class="container mt-5">
        <h2>About Us</h2>
        <p>Located in the heart of the city, Luxury Stay Hotel offers the finest amenities and services to make your stay unforgettable.</p>
        <div class="row">
            <div class="col-md-4">
                <h3>Spa and Wellness</h3>
                <p>Relax and rejuvenate with our world-class spa treatments.</p>
            </div>
            <div class="col-md-4">
                <h3>Gourmet Dining</h3>
                <p>Indulge in culinary delights crafted by our master chefs.</p>
            </div>
            <div class="col-md-4">
                <h3>Luxury Rooms</h3>
                <p>Experience comfort in our elegantly designed rooms and suites.</p>
            </div>
        </div>
    </div>
</body>
</html>
'''

booking_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Book Your Stay</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1>Book Your Stay</h1>
        <form method="post">
            <div class="form-group">
                <label for="bookingData">Enter your booking details in XML format:</label>
                <textarea class="form-control" id="bookingData" name="bookingData" rows="10"></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Submit Booking</button>
        </form>
    </div>
</body>
</html>
'''

booking_result_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Booking Result</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1>Booking Result</h1>
        <p>{{ result | safe }}</p>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/booking', methods=['GET', 'POST'])
def booking():
    if request.method == 'POST':
        xml_data = request.form['bookingData']
        try:
            # Parse the XML data (This is where the XXE vulnerability is)
            parser = lxml.etree.XMLParser(resolve_entities=True)
            tree = lxml.etree.fromstring(xml_data.encode(), parser=parser)
            # Extract the 'name' element text
            name = tree.find('name').text
            result = "Booking successful for " + name
            if 'Congratulations' in name:
                result += "<br><strong>Congratulations! You have successfully exploited the XXE vulnerability.</strong>"
        except Exception as e:
            result = "An error occurred: " + str(e)
        return render_template_string(booking_result_page, result=result)
    else:
        return render_template_string(booking_page)
if __name__ == '__main__':
        app.run(debug=True)