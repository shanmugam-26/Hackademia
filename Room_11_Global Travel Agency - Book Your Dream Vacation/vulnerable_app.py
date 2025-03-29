from flask import Flask, render_template_string, request

app = Flask(__name__)

home_page_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Global Travel Agency - Book Your Dream Vacation</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f2f2f2; margin:0; padding:0;}
        .header {background-color: #4CAF50; color: white; padding: 1em; text-align: center;}
        .container {padding: 2em;}
        .booking-form {background-color: white; padding: 2em; max-width: 600px; margin: auto; border-radius: 5px;}
        input[type=text], input[type=number], input[type=email] {width: 100%; padding: 12px; margin: 8px 0; box-sizing: border-box;}
        input[type=submit] {background-color: #4CAF50; color: white; padding: 12px; border: none; cursor: pointer;}
        input[type=submit]:hover {background-color: #45a049;}
    </style>
</head>
<body>
    <div class="header">
        <h1>Global Travel Agency</h1>
        <p>Book your dream vacation with us!</p>
    </div>
    <div class="container">
        <div class="booking-form">
            <h2>Book a Flight</h2>
            <form action="/book" method="get">
                <label for="name">Full Name:</label>
                <input type="text" id="name" name="name" required>

                <label for="email">Email Address:</label>
                <input type="email" id="email" name="email" required>

                <label for="passport_number">Passport Number:</label>
                <input type="text" id="passport_number" name="passport_number" required>

                <label for="credit_card_number">Credit Card Number:</label>
                <input type="number" id="credit_card_number" name="credit_card_number" required>

                <label for="destination">Destination:</label>
                <input type="text" id="destination" name="destination" required>

                <input type="submit" value="Book Now">
            </form>
        </div>
    </div>
</body>
</html>
'''

confirmation_page_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Booking Confirmation</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f2f2f2; margin:0; padding:0;}
        .header {background-color: #4CAF50; color: white; padding: 1em; text-align: center;}
        .container {padding: 2em;}
        .confirmation {background-color: white; padding: 2em; max-width: 600px; margin: auto; border-radius: 5px;}
        .congrats {color: green; font-weight: bold;}
    </style>
</head>
<body>
    <div class="header">
        <h1>Global Travel Agency</h1>
    </div>
    <div class="container">
        <div class="confirmation">
            {% if show_congratulations %}
            <p class="congrats">Congratulations, you have successfully exploited the Insecure Communication vulnerability!</p>
            {% else %}
            <h2>Thank you for your booking, {{ name }}!</h2>
            <p>Your trip to {{ destination }} has been booked.</p>
            {% endif %}
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page_template)

@app.route('/book', methods=['GET'])
def book():
    name = request.args.get('name')
    email = request.args.get('email')
    passport_number = request.args.get('passport_number')
    credit_card_number = request.args.get('credit_card_number')
    destination = request.args.get('destination')

    # Simulate processing booking
    # Insecure communication: Sending sensitive data via GET parameters over HTTP

    show_congratulations = False
    # Check for exploitation
    if credit_card_number == '1234567890123456':
        show_congratulations = True

    return render_template_string(confirmation_page_template, name=name, destination=destination, show_congratulations=show_congratulations)

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)