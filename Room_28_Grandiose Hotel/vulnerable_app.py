from flask import Flask, request, render_template_string
import lxml.etree as ET
import os

app = Flask(__name__)

home_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Grandiose Hotel</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #e8e8e8; margin: 0; padding: 0;}
        header {background-color: #6ab446; color: #fff; padding: 20px;}
        nav ul {list-style-type: none; padding: 0;}
        nav ul li {display: inline; margin-right: 15px;}
        nav ul li a {color: #fff; text-decoration: none; font-weight: bold;}
        .container {padding: 20px;}
        footer {background-color: #333; color: #fff; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}
    </style>
</head>
<body>
    <header>
        <h1>Welcome to Grandiose Hotel</h1>
        <nav>
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="/booking">Booking</a></li>
                <li><a href="/contact">Contact Us</a></li>
            </ul>
        </nav>
    </header>
    <div class="container">
        <h2>Your luxury stay awaits</h2>
        <p>Experience the ultimate comfort and luxury at Grandiose Hotel.</p>
        <img src="https://example.com/hotel.jpg" alt="Grandiose Hotel" width="600">
    </div>
    <footer>
        <p>&copy; 2023 Grandiose Hotel. All rights reserved.</p>
    </footer>
</body>
</html>
'''

booking_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Booking - Grandiose Hotel</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #e8e8e8;}
        .container {padding: 20px;}
        label {display: block; margin-top: 10px;}
        textarea {width: 100%; height: 200px;}
        input[type="submit"] {margin-top: 10px; padding: 10px 20px;}
    </style>
</head>
<body>
    <div class="container">
        <h1>Book Your Stay</h1>
        <form method="post" action="/booking">
            <label>Enter your booking details in XML format:</label>
            <textarea name="booking_xml"></textarea>
            <input type="submit" value="Submit Booking">
        </form>
    </div>
</body>
</html>
'''

contact_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Contact Us - Grandiose Hotel</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #e8e8e8;}
        .container {padding: 20px;}
    </style>
</head>
<body>
    <div class="container">
        <h1>Contact Us</h1>
        <p>Email: info@grandiosehotel.com</p>
        <p>Phone: +1 234 567 890</p>
        <p>Address: 123 Luxury Lane, Paradise City, Country</p>
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
        booking_xml = request.form['booking_xml']
        
        try:
            parser = ET.XMLParser(resolve_entities=True)
            root = ET.fromstring(booking_xml, parser)
            # Convert the XML back to string to include any resolved entities
            booking_info = ET.tostring(root, pretty_print=True).decode()
            response = f'''
            <h1>Booking Received</h1>
            <p>Your booking details:</p>
            <pre>{booking_info}</pre>
            '''
            if 'Congratulations' in booking_info:
                response += '<h2>Congratulations! You have successfully exploited the XXE vulnerability.</h2>'
            return response
        except Exception as e:
            return f'<h1>Error processing your booking: {str(e)}</h1>'
    else:
        return render_template_string(booking_page)

@app.route('/contact')
def contact():
    return render_template_string(contact_page)

if __name__ == '__main__':
    # Create a secret file
    if not os.path.exists('secret.txt'):
        with open('secret.txt', 'w') as f:
            f.write('Congratulations! You have successfully exploited the XXE vulnerability.')
    app.run(debug=True)