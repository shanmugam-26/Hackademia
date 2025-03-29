from flask import Flask, render_template_string, request
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = 'SuperSecretKey'

template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Wanderlust Travel Agency</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-image: url('https://via.placeholder.com/1920x1080.png?text=Travel+Background');
            background-size: cover;
            color: #333;
            margin: 0;
        }
        .header {
            background-color: rgba(255,255,255,0.8);
            padding: 20px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
        }
        .content {
            background-color: rgba(255,255,255,0.8);
            padding: 50px;
            margin: 50px;
        }
        .destination {
            margin-bottom: 30px;
        }
        .destination img {
            max-width: 100%;
            height: auto;
        }
        .destination h2 {
            margin-top: 10px;
        }
        .footer {
            text-align: center;
            padding: 20px;
            background-color: rgba(255,255,255,0.8);
            position: fixed;
            width: 100%;
            bottom: 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Wanderlust Travel Agency</h1>
        <p>Your adventure starts here.</p>
    </div>
    <div class="content">
        <div class="destination">
            <img src="https://via.placeholder.com/800x400.png?text=Destination+1" alt="Destination 1">
            <h2>Tropical Paradise</h2>
            <p>Experience the serene beauty of pristine beaches and crystal clear waters.</p>
        </div>
        <div class="destination">
            <img src="https://via.placeholder.com/800x400.png?text=Destination+2" alt="Destination 2">
            <h2>Mountain Retreat</h2>
            <p>Find peace in the majestic mountains, away from the hustle and bustle.</p>
        </div>
        <div class="destination">
            <img src="https://via.placeholder.com/800x400.png?text=Destination+3" alt="Destination 3">
            <h2>City Lights</h2>
            <p>Immerse yourself in the vibrant life of bustling cityscapes.</p>
        </div>
    </div>
    <div class="footer">
        &copy; 2023 Wanderlust Travel Agency
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(template)

@app.route('/booking')
def booking():
    destination = request.args.get('destination', '')
    if destination == '':
        return "Please provide a destination."
    else:
        if destination == 'test':
            1 / 0  # This will cause a ZeroDivisionError
        return Markup(f"Booking confirmed for {destination}!")

if __name__ == '__main__':
    app.run(debug=True)