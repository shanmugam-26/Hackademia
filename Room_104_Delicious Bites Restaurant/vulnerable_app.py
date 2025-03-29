from flask import Flask, render_template_string, request, redirect, url_for, make_response

app = Flask(__name__)

home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Delicious Bites Restaurant</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #fff8e1;
            color: #5d4037;
            margin: 0;
            padding: 0;
        }
        header {
            background-color: #ffe0b2;
            padding: 20px;
            text-align: center;
        }
        nav {
            background-color: #ffcc80;
            padding: 10px;
            text-align: center;
        }
        nav a {
            color: #5d4037;
            margin: 0 15px;
            text-decoration: none;
            font-weight: bold;
        }
        main {
            padding: 20px;
        }
        footer {
            background-color: #ffe0b2;
            padding: 10px;
            text-align: center;
            font-size: 14px;
        }
        .btn-order {
            background-color: #ff9800;
            color: #ffffff;
            padding: 15px 25px;
            text-decoration: none;
            display: inline-block;
            border-radius: 5px;
            margin-top: 20px;
        }
        .btn-order:hover {
            background-color: #fb8c00;
        }
    </style>
</head>
<body>
    <header>
        <h1>Welcome to Delicious Bites</h1>
        <p>Your favorite spot for gourmet dining</p>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/menu">Menu</a>
        <a href="/reservations">Reservations</a>
        <a href="/contact">Contact Us</a>
    </nav>
    <main>
        <h2>Experience Culinary Excellence</h2>
        <p>At Delicious Bites, we offer an exquisite selection of dishes prepared by top chefs.</p>
        <a href="/special-offer" class="btn-order">Click here for a Special Offer!</a>
    </main>
    <footer>
        <p>&copy; 2023 Delicious Bites Restaurant</p>
    </footer>
</body>
</html>
'''

congrats_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #e8f5e9;
            color: #388e3c;
            text-align: center;
            padding-top: 100px;
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
    <p>You have successfully exploited the Clickjacking vulnerability.</p>
</body>
</html>
'''

@app.route('/')
def home():
    response = make_response(render_template_string(home_page))
    # Intentionally omitting anti-clickjacking headers to simulate vulnerability
    # e.g., 'X-Frame-Options' header is not set
    return response

@app.route('/special-offer', methods=['GET', 'POST'])
def special_offer():
    if request.method == 'POST':
        return redirect(url_for('congratulations'))
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Special Offer</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #fff8e1;
                color: #5d4037;
                text-align: center;
                padding-top: 50px;
            }
            form {
                display: inline-block;
                margin-top: 20px;
            }
            input[type="submit"] {
                background-color: #ff9800;
                color: #ffffff;
                padding: 10px 20px;
                border: none;
                border-radius: 5px;
                cursor: pointer;
            }
            input[type="submit"]:hover {
                background-color: #fb8c00;
            }
        </style>
    </head>
    <body>
        <h2>Exclusive Deal!</h2>
        <p>Fill out the form to claim your special offer.</p>
        <form action="/special-offer" method="post">
            <input type="hidden" name="claim" value="offer">
            <input type="submit" value="Claim Offer">
        </form>
    </body>
    </html>
    '''

@app.route('/congratulations')
def congratulations():
    return render_template_string(congrats_page)

# Additional routes to enhance the complexity and realism
@app.route('/menu')
def menu():
    return '''
    <h2>Our Menu</h2>
    <p>Discover our delicious menu items.</p>
    '''

@app.route('/reservations')
def reservations():
    return '''
    <h2>Reservations</h2>
    <p>Book a table online.</p>
    '''

@app.route('/contact')
def contact():
    return '''
    <h2>Contact Us</h2>
    <p>Get in touch with us.</p>
    '''

if __name__ == '__main__':
    app.run(debug=True)