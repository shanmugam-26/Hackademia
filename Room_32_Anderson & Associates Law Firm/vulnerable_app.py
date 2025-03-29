from flask import Flask, request, render_template_string, send_file, redirect, url_for, abort
import os

app = Flask(__name__)

# Simulated file storage
DOCUMENTS_FOLDER = 'documents'
if not os.path.exists(DOCUMENTS_FOLDER):
    os.makedirs(DOCUMENTS_FOLDER)
    # Create some dummy documents
    with open(os.path.join(DOCUMENTS_FOLDER, 'case1.txt'), 'w') as f:
        f.write('Confidential Document: Case 1 Details...\nLorem ipsum dolor sit amet, consectetur adipiscing elit.')
    with open(os.path.join(DOCUMENTS_FOLDER, 'case2.txt'), 'w') as f:
        f.write('Confidential Document: Case 2 Details...\nSed do eiusmod tempor incididunt ut labore et dolore magna aliqua.')
    # Hidden congratulatory file
    with open(os.path.join(DOCUMENTS_FOLDER, 'congratulations.txt'), 'w') as f:
        f.write('Congratulations! You have successfully exploited the directory traversal vulnerability!')

@app.route('/')
def index():
    home_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Anderson & Associates Law Firm</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
            .header { background-color: #003366; color: white; padding: 20px; text-align: center; }
            .header h1 { margin: 0; }
            .nav { margin: 15px 0; padding: 0; list-style-type: none; text-align: center; }
            .nav li { display: inline; margin: 0 10px; }
            .nav a { color: white; text-decoration: none; font-weight: bold; }
            .content { padding: 20px; }
            .footer { background-color: #003366; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
            .banner { background-image: url('https://www.law.com/image/law-firm.jpg'); background-size: cover; height: 300px; position: relative; }
            .banner-text { position: absolute; bottom: 30px; left: 30px; color: white; font-size: 2em; }
            .btn { background-color: #0066cc; color: white; padding: 10px 20px; text-decoration: none; }
            .btn:hover { background-color: #004d99; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Anderson & Associates Law Firm</h1>
            <ul class="nav">
                <li><a href="/">Home</a></li>
                <li><a href="/about">About Us</a></li>
                <li><a href="/documents">Documents</a></li>
                <li><a href="/contact">Contact</a></li>
            </ul>
        </div>
        <div class="banner">
            <div class="banner-text">Expert Legal Solutions</div>
        </div>
        <div class="content">
            <h2>Welcome to Anderson & Associates</h2>
            <p>Providing professional legal services since 1990. Our team of experienced attorneys is dedicated to delivering top-notch legal representation to individuals and businesses alike.</p>
            <a href="/about" class="btn">Learn More</a>
        </div>
        <div class="footer">
            <p>&copy; 2023 Anderson & Associates Law Firm</p>
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
        <title>About Us - Anderson & Associates Law Firm</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
            /* Add same styles from the index page */
            .header { background-color: #003366; color: white; padding: 20px; text-align: center; }
            .header h1 { margin: 0; }
            .nav { margin: 15px 0; padding: 0; list-style-type: none; text-align: center; }
            .nav li { display: inline; margin: 0 10px; }
            .nav a { color: white; text-decoration: none; font-weight: bold; }
            .content { padding: 20px; }
            .footer { background-color: #003366; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
            .team-member { margin-bottom: 20px; }
            .team-member h3 { margin-bottom: 5px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Anderson & Associates Law Firm</h1>
            <ul class="nav">
                <li><a href="/">Home</a></li>
                <li><a href="/about">About Us</a></li>
                <li><a href="/documents">Documents</a></li>
                <li><a href="/contact">Contact</a></li>
            </ul>
        </div>
        <div class="content">
            <h2>About Us</h2>
            <p>At Anderson & Associates, we are committed to providing exceptional legal services. Our team of dedicated attorneys specializes in various fields of law to meet all your legal needs.</p>
            <h3>Our Team</h3>
            <div class="team-member">
                <h3>John Anderson</h3>
                <p>Founder & Senior Partner</p>
            </div>
            <div class="team-member">
                <h3>Emily Clark</h3>
                <p>Partner - Corporate Law</p>
            </div>
            <div class="team-member">
                <h3>Michael Smith</h3>
                <p>Partner - Criminal Defense</p>
            </div>
        </div>
        <div class="footer">
            <p>&copy; 2023 Anderson & Associates Law Firm</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(about_page)

@app.route('/documents')
def documents():
    doc_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Documents - Anderson & Associates Law Firm</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
            /* Add same styles from the index page */
            .header { background-color: #003366; color: white; padding: 20px; text-align: center; }
            .header h1 { margin: 0; }
            .nav { margin: 15px 0; padding: 0; list-style-type: none; text-align: center; }
            .nav li { display: inline; margin: 0 10px; }
            .nav a { color: white; text-decoration: none; font-weight: bold; }
            .content { padding: 20px; }
            .footer { background-color: #003366; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
            .document-list { list-style-type: none; padding: 0; }
            .document-list li { margin-bottom: 5px; }
            .document-list a { text-decoration: none; color: #0066cc; }
            .document-list a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Anderson & Associates Law Firm</h1>
            <ul class="nav">
                <li><a href="/">Home</a></li>
                <li><a href="/about">About Us</a></li>
                <li><a href="/documents">Documents</a></li>
                <li><a href="/contact">Contact</a></li>
            </ul>
        </div>
        <div class="content">
            <h2>Client Documents</h2>
            <p>Access your case documents securely below:</p>
            <ul class="document-list">
                <li><a href="/view?file=case1.txt">Case 1</a></li>
                <li><a href="/view?file=case2.txt">Case 2</a></li>
            </ul>
        </div>
        <div class="footer">
            <p>&copy; 2023 Anderson & Associates Law Firm</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(doc_page)

@app.route('/contact')
def contact():
    contact_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - Anderson & Associates Law Firm</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
            /* Add same styles from the index page */
            .header { background-color: #003366; color: white; padding: 20px; text-align: center; }
            .header h1 { margin: 0; }
            .nav { margin: 15px 0; padding: 0; list-style-type: none; text-align: center; }
            .nav li { display: inline; margin: 0 10px; }
            .nav a { color: white; text-decoration: none; font-weight: bold; }
            .content { padding: 20px; }
            .footer { background-color: #003366; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
            .contact-form { max-width: 600px; margin: auto; }
            .contact-form label { display: block; margin-bottom: 5px; }
            .contact-form input, .contact-form textarea { width: 100%; margin-bottom: 10px; padding: 8px; }
            .contact-form button { padding: 10px 20px; background-color: #0066cc; color: white; border: none; }
            .contact-form button:hover { background-color: #004d99; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Anderson & Associates Law Firm</h1>
            <ul class="nav">
                <li><a href="/">Home</a></li>
                <li><a href="/about">About Us</a></li>
                <li><a href="/documents">Documents</a></li>
                <li><a href="/contact">Contact</a></li>
            </ul>
        </div>
        <div class="content">
            <h2>Contact Us</h2>
            <div class="contact-form">
                <form method="post" action="/contact">
                    <label for="name">Name:</label>
                    <input type="text" id="name" name="name" required>
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required>
                    <label for="message">Message:</label>
                    <textarea id="message" name="message" rows="6" required></textarea>
                    <button type="submit">Send Message</button>
                </form>
            </div>
        </div>
        <div class="footer">
            <p>&copy; 2023 Anderson & Associates Law Firm</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(contact_page)

@app.route('/contact', methods=['POST'])
def contact_form():
    # Dummy handler for form submission
    return redirect(url_for('contact_success'))

@app.route('/contact-success')
def contact_success():
    success_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - Anderson & Associates Law Firm</title>
        <style>
            /* Same styles as before */
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Anderson & Associates Law Firm</h1>
        </div>
        <div class="content">
            <h2>Thank You!</h2>
            <p>Your message has been received. We will get back to you shortly.</p>
        </div>
        <div class="footer">
            <p>&copy; 2023 Anderson & Associates Law Firm</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(success_page)

@app.route('/view')
def view():
    # Get the filename from the query parameter
    filename = request.args.get('file')
    if not filename:
        return redirect(url_for('documents'))
    # Directory traversal vulnerability
    filepath = os.path.join(DOCUMENTS_FOLDER, filename)
    try:
        # Read and return the file content
        with open(filepath, 'r') as f:
            content = f.read()
        # If user finds the hidden 'congratulations.txt' file, show special message
        if 'congratulations' in filename.lower():
            content = '''
            <h2>Congratulations!</h2>
            <p>You have successfully exploited the directory traversal vulnerability!</p>
            <pre>{}</pre>
            '''.format(content)
        else:
            content = '<pre>{}</pre>'.format(content)
        return content
    except FileNotFoundError:
        abort(404)
    except Exception as e:
        abort(500)

if __name__ == '__main__':
    app.run(debug=True)