from flask import Flask, request, render_template_string, send_file, abort
import os

app = Flask(__name__)

# Create necessary directories and files
def setup_files():
    # Create 'files' directory if it doesn't exist
    if not os.path.exists('files'):
        os.mkdir('files')

    # Create example file in 'files' directory
    if not os.path.exists('files/policy_terms.pdf'):
        with open('files/policy_terms.pdf', 'w') as f:
            f.write('Policy Terms and Conditions...')

    # Create 'congratulations.txt' outside 'files' directory
    if not os.path.exists('congratulations.txt'):
        with open('congratulations.txt', 'w') as f:
            f.write('Congratulations! You have successfully exploited the vulnerability.')

    # Create a secret directory and file
    if not os.path.exists('secret'):
        os.mkdir('secret')
    if not os.path.exists('secret/flag.txt'):
        with open('secret/flag.txt', 'w') as f:
            f.write('FLAG{directory_traversal_success}')

setup_files()

@app.route('/')
def home():
    # Return the main page
    html_content = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureLife Insurance</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; }
            header { background-color: #0074D9; color: #fff; padding: 20px; text-align: center; }
            nav { margin: 0; padding: 10px; background-color: #333; }
            nav a { color: #fff; margin: 0 15px; text-decoration: none; }
            nav a:hover { text-decoration: underline; }
            .container { padding: 20px; }
            footer { background-color: #0074D9; color: #fff; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
            a.button { background-color: #0074D9; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
            a.button:hover { background-color: #005F9E; }
        </style>
    </head>
    <body>
        <header>
            <h1>SecureLife Insurance</h1>
            <p>Your trusted partner in securing your future.</p>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/about">About Us</a>
            <a href="/policies">Policies</a>
            <a href="/contact">Contact</a>
        </nav>
        <div class="container">
            <h2>Welcome to SecureLife Insurance</h2>
            <p>At SecureLife, we provide top-notch insurance services to secure your life and assets.</p>
            <p>Download our <a href="/download?file=policy_terms.pdf" class="button">Policy Terms and Conditions</a></p>
        </div>
        <footer>
            &copy; 2023 SecureLife Insurance Co.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/about')
def about():
    html_content = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>About Us - SecureLife Insurance</title>
        <style>
            /* Include your CSS styles here */
        </style>
    </head>
    <body>
        <!-- Repeat header and nav from home page -->
        <header>
            <h1>SecureLife Insurance</h1>
            <p>Your trusted partner in securing your future.</p>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/about">About Us</a>
            <a href="/policies">Policies</a>
            <a href="/contact">Contact</a>
        </nav>
        <div class="container">
            <h2>About Us</h2>
            <p>SecureLife Insurance has been serving customers since 1990, providing reliable and affordable insurance solutions tailored to individual needs.</p>
        </div>
        <!-- Repeat footer from home page -->
        <footer>
            &copy; 2023 SecureLife Insurance Co.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/policies')
def policies():
    html_content = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Our Policies - SecureLife Insurance</title>
        <style>
            /* Include your CSS styles here */
        </style>
    </head>
    <body>
        <!-- Repeat header and nav from home page -->
        <header>
            <h1>SecureLife Insurance</h1>
            <p>Your trusted partner in securing your future.</p>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/about">About Us</a>
            <a href="/policies">Policies</a>
            <a href="/contact">Contact</a>
        </nav>
        <div class="container">
            <h2>Our Policies</h2>
            <p>We offer a range of policies including life insurance, health insurance, and property insurance to protect you and your loved ones.</p>
        </div>
        <!-- Repeat footer from home page -->
        <footer>
            &copy; 2023 SecureLife Insurance Co.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/contact')
def contact():
    html_content = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - SecureLife Insurance</title>
        <style>
            /* Include your CSS styles here */
        </style>
    </head>
    <body>
        <!-- Repeat header and nav from home page -->
        <header>
            <h1>SecureLife Insurance</h1>
            <p>Your trusted partner in securing your future.</p>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/about">About Us</a>
            <a href="/policies">Policies</a>
            <a href="/contact">Contact</a>
        </nav>
        <div class="container">
            <h2>Contact Us</h2>
            <p>Have any questions? We'd love to hear from you. Reach out to us at (555) 123-4567 or email us at support@securelife.com.</p>
        </div>
        <!-- Repeat footer from home page -->
        <footer>
            &copy; 2023 SecureLife Insurance Co.
        </footer>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    # Vulnerable code allowing directory traversal
    filepath = os.path.join('files', filename)
    try:
        # Attempt to send the requested file
        return send_file(filepath)
    except FileNotFoundError:
        abort(404)

if __name__ == '__main__':
    app.run()