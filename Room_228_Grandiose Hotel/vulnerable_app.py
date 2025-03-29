from flask import Flask, render_template_string, request, abort
import os

app = Flask(__name__)

template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grandiose Hotel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-image: url('https://source.unsplash.com/1600x900/?hotel,luxury');
            background-size: cover;
            background-repeat: no-repeat;
            background-attachment: fixed;
            color: white;
        }
        .overlay {
            background: rgba(0, 0, 0, 0.6);
            min-height: 100vh;
        }
        .centered {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
        }
        .btn-custom {
            background-color: #f8c146;
            border-color: #f8c146;
            color: #333;
        }
        .btn-custom:hover {
            background-color: #e0ab1e;
            border-color: #e0ab1e;
            color: white;
        }
    </style>
</head>
<body>
    <div class="overlay text-center">
        <div class="centered">
            <h1>Welcome to Grandiose Hotel</h1>
            <p>Experience luxury like never before.</p>
            <form action="/booking" method="post">
                <button type="submit" class="btn btn-custom btn-lg">Book Your Stay</button>
            </form>
        </div>
    </div>
</body>
</html>
'''

booking_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Book Your Stay</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #fff;
            color: #333;
            padding-top: 50px;
        }
        .container {
            max-width: 500px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Book Your Luxury Stay</h2>
        <form action="/confirm" method="post">
            <div class="form-group">
                <label for="name">Full Name</label>
                <input type="text" class="form-control" id="name" name="name" required>
            </div>
            <div class="form-group">
                <label for="room">Room Type</label>
                <select class="form-control" id="room" name="room">
                    <option>Deluxe Suite</option>
                    <option>Presidential Suite</option>
                    <option>Royal Suite</option>
                </select>
            </div>
            <button type="submit" class="btn btn-custom btn-block">Confirm Booking</button>
        </form>
    </div>
</body>
</html>
'''

congrats_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #28a745;
            color: #fff;
            text-align: center;
            padding-top: 200px;
        }
        h1 {
            font-size: 48px;
        }
        p {
            font-size: 24px;
        }
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the vulnerability.</p>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def home():
    return render_template_string(template)

@app.route('/booking', methods=['POST'])
def booking():
    return render_template_string(booking_template)

@app.route('/confirm', methods=['POST'])
def confirm():
    name = request.form.get('name')
    room = request.form.get('room')
    return f"Thank you {name}, your {room} has been booked!"

@app.route('/admin')
def admin():
    config_debug = os.getenv('DEBUG_MODE', 'False')
    if config_debug == 'True':
        return render_template_string(congrats_template)
    else:
        abort(403)

if __name__ == '__main__':
    app.run()
