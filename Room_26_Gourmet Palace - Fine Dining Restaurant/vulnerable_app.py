from flask import Flask, render_template_string, request, redirect, url_for
import base64

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Gourmet Palace - Fine Dining Restaurant</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-image: url('https://example.com/restaurant.jpg');
                background-size: cover;
                margin: 0;
                padding: 0;
                color: #333;
            }
            .header {
                background-color: rgba(255, 255, 255, 0.8);
                padding: 20px;
                text-align: center;
            }
            .content {
                background-color: rgba(255, 255, 255, 0.8);
                padding: 20px;
                margin: 50px;
            }
            .button {
                background-color: #4CAF50;
                color: white;
                padding: 14px 20px;
                margin: 8px 0;
                border: none;
                cursor: pointer;
                width: 100%;
                text-align: center;
            }
            .button:hover {
                background-color: #45a049;
            }
            a {
                color: white;
                text-decoration: none;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome to Gourmet Palace</h1>
            <h3>Experience the finest dining in the city</h3>
        </div>
        <div class="content">
            <p>Join us for an exquisite culinary journey. Our chefs prepare the finest dishes with the freshest ingredients.</p>
            <p>Make a reservation today!</p>
            <a href="/reservation" class="button">Reserve a Table</a>
        </div>
    </body>
    </html>
    ''')

@app.route('/reservation')
def reservation():
    next_param = request.args.get('next', '')
    # Encode the next parameter
    next_encoded = base64.urlsafe_b64encode(next_param.encode()).decode()
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Gourmet Palace - Reservation</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f2f2f2;
                margin: 0;
                padding: 0;
                color: #333;
            }
            .header {
                padding: 20px;
                text-align: center;
            }
            .content {
                padding: 20px;
                margin: 50px;
            }
            input[type=text], input[type=date], input[type=time], input[type=number] {
                width: 100%;
                padding: 12px;
                margin: 8px 0;
                box-sizing: border-box;
            }
            input[type=submit] {
                width: 100%;
                background-color: #4CAF50;
                color: white;
                padding: 14px 20px;
                margin: 8px 0;
                border: none;
                cursor: pointer;
            }
            input[type=submit]:hover {
                background-color: #45a049;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Reservation Form</h1>
        </div>
        <div class="content">
            <form action="/process_reservation" method="POST">
                Name: <input type="text" name="name"><br>
                Date: <input type="date" name="date"><br>
                Time: <input type="time" name="time"><br>
                Number of Guests: <input type="number" name="guests"><br>
                <input type="hidden" name="next" value="{{ next_encoded }}">
                <input type="submit" value="Reserve">
            </form>
        </div>
    </body>
    </html>
    ''', next_encoded=next_encoded)

@app.route('/process_reservation', methods=['POST'])
def process_reservation():
    name = request.form.get('name')
    date = request.form.get('date')
    time = request.form.get('time')
    guests = request.form.get('guests')
    next_encoded = request.form.get('next', '')
    # Decode the next parameter
    try:
        next_url = base64.urlsafe_b64decode(next_encoded.encode()).decode()
    except Exception as e:
        next_url = ''

    # Normally, would process the reservation here
    # For this example, we will skip processing

    # If next_url is provided, redirect to it
    if next_url:
        return redirect(next_url)
    else:
        # Redirect to a default thank you page
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reservation Confirmed</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f2f2f2;
                    margin: 0;
                    padding: 0;
                    color: #333;
                }
                .header {
                    padding: 20px;
                    text-align: center;
                }
                .content {
                    padding: 20px;
                    margin: 50px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Thank You, {{ name }}!</h1>
            </div>
            <div class="content">
                <p>Your reservation on {{ date }} at {{ time }} for {{ guests }} guests has been confirmed.</p>
            </div>
        </body>
        </html>
        ''', name=name, date=date, time=time, guests=guests)

# Congratulations route
@app.route('/congratulations')
def congratulations():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Congratulations!</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f2f2f2;
                margin: 0;
                padding: 0;
                color: #333;
            }
            .header {
                padding: 20px;
                text-align: center;
            }
            .content {
                padding: 20px;
                margin: 50px;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Congratulations!</h1>
        </div>
        <div class="content">
            <p>You have successfully exploited the unvalidated redirect vulnerability.</p>
        </div>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    app.run(debug=True)