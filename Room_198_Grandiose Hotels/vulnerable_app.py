from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

home_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Grandiose Hotels</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-image: url('https://www.example.com/hotel.jpg');
            background-size: cover;
            color: #fff;
        }
        .overlay {
            background-color: rgba(0,0,0,0.6);
            padding: 50px;
            border-radius: 10px;
            margin-top: 100px;
        }
        .btn-custom {
            background-color: #ffcc00;
            border-color: #ffcc00;
            color: #000;
        }
    </style>
</head>
<body>
<div class="container text-center">
    <div class="overlay">
        <h1>Welcome to Grandiose Hotels</h1>
        <p>Experience luxury like never before.</p>
        <a href="/booking" class="btn btn-custom btn-lg mt-3">Book Now</a>
    </div>
</div>
</body>
</html>
'''

booking_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Booking - Grandiose Hotels</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #f2f2f2;
        }
        .booking-form {
            background-color: #fff;
            padding: 40px;
            margin-top: 50px;
            border-radius: 10px;
        }
        .btn-custom {
            background-color: #ffcc00;
            border-color: #ffcc00;
            color: #000;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="booking-form">
        <h2 class="text-center">Online Booking</h2>
        <form method="post" action="/booking">
            <div class="form-group">
                <label for="booking">Upload Your Booking Details (XML):</label>
                <textarea class="form-control" name="booking" rows="10" placeholder="Enter XML here..."></textarea>
            </div>
            <button type="submit" class="btn btn-custom btn-block">Submit Booking</button>
        </form>
    </div>
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
        xml_data = request.form['booking']
        try:
            parser = etree.XMLParser()
            root = etree.fromstring(xml_data, parser)
            # Process the XML data
            customer_name = root.findtext('name')
            room_type = root.findtext('room')
            special_requests = root.findtext('requests')
            response = f"""
            <div style='text-align: center; margin-top: 50px;'>
                <h2>Booking Confirmation</h2>
                <p>Thank you, {customer_name}, for choosing Grandiose Hotels.</p>
                <p>Your {room_type} room has been booked successfully.</p>
                <p>Special Requests: {special_requests}</p>
            </div>
            """
            if "congratulations" in special_requests.lower():
                response += "<h3 style='color: green; text-align: center;'>Congratulations! You have successfully exploited the XXE vulnerability!</h3>"
            return render_template_string(response)
        except Exception as e:
            return render_template_string(f"""
                <div style='text-align: center; margin-top: 50px;'>
                    <h2>Error Processing Your Booking</h2>
                    <p>{e}</p>
                </div>
            """)
    else:
        return render_template_string(booking_page)
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)