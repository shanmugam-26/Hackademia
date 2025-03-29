from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

HOME_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Grand Royal Hotel</title>
    <style>
        /* CSS styles to make it attractive and professional */
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; }
        header { background-color: #333; padding: 20px; color: white; text-align: center; }
        header h1 { margin: 0; }
        nav a { margin: 0 15px; color: white; text-decoration: none; font-weight: bold; }
        .content { padding: 40px; }
        h2 { color: #333; }
        .booking-form { background-color: white; padding: 30px; border-radius: 5px; max-width: 600px; margin: auto; }
        label { display: block; margin-bottom: 10px; color: #555; }
        input[type="file"] { margin-bottom: 20px; }
        input[type="submit"] { background-color: #333; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        input[type="submit"]:hover { background-color: #555; }
    </style>
</head>
<body>
    <header>
        <h1>Welcome to the Grand Royal Hotel</h1>
        <nav>
            <a href="#">Home</a>
            <a href="#">Rooms</a>
            <a href="#">Dining</a>
            <a href="#">Events</a>
            <a href="#">Contact Us</a>
        </nav>
    </header>
    <div class="content">
        <h2>Book Your Stay</h2>
        <p>Experience luxury like never before. Please fill out the form below to book your stay with us.</p>
        <div class="booking-form">
            <form method="post" enctype="multipart/form-data">
                <label for="booking_file">Upload your booking details (XML file):</label>
                <input type="file" id="booking_file" name="booking_file" accept=".xml" required>
                <input type="submit" value="Submit Booking">
            </form>
        </div>
    </div>
</body>
</html>
'''

CONGRATS_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Booking Confirmation</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; text-align: center; padding-top: 50px; }
        h1 { color: #4CAF50; }
        p { font-size: 18px; color: #555; }
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the XXE vulnerability!</p>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        xml_data = request.files['booking_file'].read()
        # Process the XML data
        try:
            parser = etree.XMLParser(resolve_entities=True)
            tree = etree.fromstring(xml_data, parser)
            # Extract data from XML
            name = tree.findtext('name')
            date = tree.findtext('date')
            # Check for the secret value set via XXE
            secret = tree.findtext('secret')
            if secret and 'congrats' in secret.lower():
                return render_template_string(CONGRATS_PAGE)
            else:
                return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Booking Failed</title>
                    <style>
                        body { font-family: Arial, sans-serif; background-color: #f2f2f2; text-align: center; padding-top: 50px; }
                        h1 { color: #E74C3C; }
                        p { font-size: 18px; color: #555; }
                    </style>
                </head>
                <body>
                    <h1>Booking Failed</h1>
                    <p>Invalid data provided. Please try again.</p>
                </body>
                </html>
                ''')
        except Exception as e:
            return "An error occurred while processing your booking.", 500
    return render_template_string(HOME_PAGE)

if __name__ == '__main__':
    app.run(debug=True)