from flask import Flask, render_template_string, request

app = Flask(__name__)

# Secret flag variable
flag = "Congratulations! You have discovered the secret flag: FLAG{SSTI_Exploited_Successfully}"

@app.route('/')
def index():
    home_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureLife Insurance Company</title>
        <style>
            body {font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4;}
            header {background-color: #003366; color: #ffffff; padding: 20px; text-align: center;}
            nav {background-color: #006699; color: #ffffff; padding: 15px; text-align: center;}
            nav a {color: #ffffff; margin: 0 15px; text-decoration: none; font-weight: bold;}
            .content {padding: 20px;}
            footer {background-color: #003366; color: #ffffff; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}
        </style>
    </head>
    <body>
        <header>
            <h1>SecureLife Insurance Company</h1>
            <p>Your trusted partner in securing your future.</p>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/about">About Us</a>
            <a href="/products">Products</a>
            <a href="/contact">Contact Us</a>
            <a href="/feedback">Feedback</a>
        </nav>
        <div class="content">
            <h2>Welcome to SecureLife Insurance</h2>
            <p>At SecureLife, we are committed to providing top-notch insurance services that cater to all your needs. Our range of products ensures that you and your loved ones are protected at all times.</p>
            <p>Explore our website to know more about our offerings.</p>
        </div>
        <footer>
            &copy; 2023 SecureLife Insurance Company
        </footer>
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
        <title>About Us - SecureLife Insurance Company</title>
        <style>
            /* Reuse the style from the index page */
        </style>
    </head>
    <body>
        <header>
            <h1>About SecureLife Insurance</h1>
        </header>
        <div class="content">
            <p>SecureLife Insurance Company has been serving customers since 1990, providing reliable and affordable insurance solutions.</p>
        </div>
        <footer>
            &copy; 2023 SecureLife Insurance Company
        </footer>
    </body>
    </html>
    '''
    return render_template_string(about_page)

@app.route('/products')
def products():
    products_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Our Products - SecureLife Insurance Company</title>
        <style>
            /* Reuse the style from the index page */
        </style>
    </head>
    <body>
        <header>
            <h1>Our Insurance Products</h1>
        </header>
        <div class="content">
            <ul>
                <li>Life Insurance</li>
                <li>Health Insurance</li>
                <li>Vehicle Insurance</li>
                <li>Home Insurance</li>
                <li>Travel Insurance</li>
            </ul>
        </div>
        <footer>
            &copy; 2023 SecureLife Insurance Company
        </footer>
    </body>
    </html>
    '''
    return render_template_string(products_page)

@app.route('/contact')
def contact():
    contact_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - SecureLife Insurance Company</title>
        <style>
            /* Reuse the style from the index page */
        </style>
    </head>
    <body>
        <header>
            <h1>Contact SecureLife Insurance</h1>
        </header>
        <div class="content">
            <p>Email: support@securelife.com</p>
            <p>Phone: +1-800-123-4567</p>
            <p>Address: 123 Secure Street, Safe City, Country</p>
        </div>
        <footer>
            &copy; 2023 SecureLife Insurance Company
        </footer>
    </body>
    </html>
    '''
    return render_template_string(contact_page)

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        comments = request.form.get('comments', '')
        template = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Feedback Received - SecureLife Insurance Company</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
                .container {padding: 50px;}
                h1 {color: #006699;}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Thank you for your feedback!</h1>
                <p>Your comments:</p>
                <blockquote>
                    {{ comments }}
                </blockquote>
            </div>
        </body>
        </html>
        '''
        # Intentionally vulnerable to SSTI
        return render_template_string(template, comments=comments)
    else:
        feedback_form = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Feedback - SecureLife Insurance Company</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
                .container {padding: 50px;}
                textarea {width: 100%; height: 100px;}
                input[type="submit"] {padding: 10px 20px; background-color: #006699; color: #ffffff; border: none; cursor: pointer;}
                input[type="submit"]:hover {background-color: #003366;}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>We value your feedback</h1>
                <form method="post">
                    <p>Please leave your comments below:</p>
                    <textarea name="comments" required></textarea><br><br>
                    <input type="submit" value="Submit Feedback">
                </form>
            </div>
        </body>
        </html>
        '''
        return render_template_string(feedback_form)

if __name__ == '__main__':
    app.run(debug=True)