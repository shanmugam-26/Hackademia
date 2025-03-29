from flask import Flask, request, render_template_string, send_file
import os

app = Flask(__name__)

# Ensure the 'documents' directory exists
if not os.path.exists('documents'):
    os.makedirs('documents')

# Create some sample documents if they don't exist
if not os.path.exists('documents/policy1.pdf'):
    with open('documents/policy1.pdf', 'w') as f:
        f.write('This is Policy Document 1.')

if not os.path.exists('documents/policy2.pdf'):
    with open('documents/policy2.pdf', 'w') as f:
        f.write('This is Policy Document 2.')

# Create the secret file outside the 'documents' directory
if not os.path.exists('secret.txt'):
    with open('secret.txt', 'w') as f:
        f.write('Congratulations! You have found the secret file by exploiting the directory traversal vulnerability.')

homepage_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>SecureLife Insurance Company</title>
    <style>
        body { font-family: Arial, sans-serif; }
        header { background-color: #004080; color: white; padding: 20px; }
        nav { margin: 0; padding: 10px; background-color: #e0e0e0; }
        nav a { margin: 10px; text-decoration: none; color: #004080; }
        footer { background-color: #004080; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
        .content { padding: 20px; }
    </style>
</head>
<body>
    <header>
        <h1>SecureLife Insurance Company</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/services">Services</a>
        <a href="/documents">Client Documents</a>
        <a href="/contact">Contact Us</a>
    </nav>
    <div class="content">
        <h2>Welcome to SecureLife Insurance Company</h2>
        <p>Your trusted partner in securing your future.</p>
        <p>At SecureLife, we offer a range of insurance products tailored to your needs.</p>
    </div>
    <footer>
        &copy; 2023 SecureLife Insurance Company
    </footer>
</body>
</html>
'''

documents_page_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Client Documents - SecureLife Insurance Company</title>
    <style>
        body { font-family: Arial, sans-serif; }
        header { background-color: #004080; color: white; padding: 20px; }
        nav { margin: 0; padding: 10px; background-color: #e0e0e0; }
        nav a { margin: 10px; text-decoration: none; color: #004080; }
        .content { padding: 20px; }
        footer { background-color: #004080; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
        form { margin-top: 20px; }
    </style>
</head>
<body>
    <header>
        <h1>SecureLife Insurance Company</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/services">Services</a>
        <a href="/documents">Client Documents</a>
        <a href="/contact">Contact Us</a>
    </nav>
    <div class="content">
        <h2>Client Documents</h2>
        <p>Please enter the document name to download your policy documents.</p>
        <form action="/documents" method="get">
            <label for="filename">Document Name:</label>
            <input type="text" id="filename" name="filename" required>
            <input type="submit" value="Download">
        </form>
    </div>
    <footer>
        &copy; 2023 SecureLife Insurance Company
    </footer>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(homepage_html)

@app.route('/documents')
def documents():
    filename = request.args.get('filename')
    if filename:
        try:
            # Vulnerable to directory traversal
            return send_file(os.path.join('documents', filename))
        except Exception as e:
            return 'Document not found.'
    else:
        return render_template_string(documents_page_html)

# Placeholder routes for additional pages
@app.route('/about')
def about():
    return render_template_string('<h1>About Us</h1><p>Information about the company.</p>')

@app.route('/services')
def services():
    return render_template_string('<h1>Our Services</h1><p>Details of services offered.</p>')

@app.route('/contact')
def contact():
    return render_template_string('<h1>Contact Us</h1><p>Contact information.</p>')

if __name__ == '__main__':
    app.run(debug=True)