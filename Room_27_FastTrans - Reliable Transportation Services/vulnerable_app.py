from flask import Flask, render_template_string, request
import os

app = Flask(__name__)

# Misconfiguration: Debug mode is enabled (should be False in production)
app.config['DEBUG'] = True  # Security misconfiguration

# Secret key is set to a known value (should be random and kept secret)
app.secret_key = 'secret_key'  # Misconfigured secret key

# Write the hidden message to a file
with open('secret.txt', 'w') as f:
    f.write('Congratulations! You have found the secret message.')

# Route for the home page
@app.route('/')
def home():
    # A simple home page with some transportation service details
    home_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>FastTrans - Reliable Transportation Services</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0;}
            .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center;}
            .nav { overflow: hidden; background-color: #333;}
            .nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                     padding: 14px 16px; text-decoration: none;}
            .nav a:hover { background-color: #ddd; color: black;}
            .container { padding: 20px; }
            .footer { background-color: #333; color: white; text-align: center; padding: 10px;
                      position: fixed; left: 0; bottom: 0; width: 100%;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>FastTrans</h1>
            <p>Your Reliable Transportation Partner</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/about">About Us</a>
            <a href="/services">Services</a>
            <a href="/contact">Contact</a>
        </div>
        <div class="container">
            <h2>Welcome to FastTrans!</h2>
            <p>At FastTrans, we provide top-notch transportation services tailored to your needs.</p>
        </div>
        <div class="footer">
            <p>&copy; 2023 FastTrans Transportation Services</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(home_page)

@app.route('/about')
def about():
    about_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>About Us - FastTrans</title>
        <style>
            /* Styles omitted for brevity */
        </style>
    </head>
    <body>
        <div class="header">
            <h1>About FastTrans</h1>
        </div>
        <div class="container">
            <p>FastTrans has been providing reliable transportation services since 2001.</p>
        </div>
        <div class="footer">
            <p>&copy; 2023 FastTrans Transportation Services</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(about_page)

@app.route('/services')
def services():
    services_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Our Services - FastTrans</title>
        <style>
            /* Styles omitted for brevity */
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Our Services</h1>
        </div>
        <div class="container">
            <ul>
                <li>Passenger Transport</li>
                <li>Freight Shipping</li>
                <li>Logistics Solutions</li>
            </ul>
        </div>
        <div class="footer">
            <p>&copy; 2023 FastTrans Transportation Services</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(services_page)

@app.route('/contact')
def contact():
    contact_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - FastTrans</title>
        <style>
            /* Styles omitted for brevity */
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Contact Us</h1>
        </div>
        <div class="container">
            <p>Email: info@fasttrans.com</p>
            <p>Phone: (123) 456-7890</p>
        </div>
        <div class="footer">
            <p>&copy; 2023 FastTrans Transportation Services</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(contact_page)

# Misconfigured route that can be exploited (Directory Traversal)
@app.route('/view')
def view_file():
    filename = request.args.get('file')
    if not filename:
        return 'No file specified.'
    try:
        # Misconfiguration: Not sanitizing user input leading to directory traversal
        with open(filename, 'r') as f:
            content = f.read()
        return f'<pre>{content}</pre>'
    except Exception as e:
        return f'Error: {e}'

if __name__ == '__main__':
    app.run(host='0.0.0.0')