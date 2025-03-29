from flask import Flask, render_template_string, request
from lxml import etree

app = Flask(__name__)

# Create a secret file
with open('secret.txt', 'w') as f:
    f.write('Congratulations! You have found the secret message.')

@app.route('/')
def index():
    return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Acme Software Solutions</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
            <style>
            body {
                padding-top: 56px;
            }
            </style>
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
              <div class="container">
                <a class="navbar-brand" href="#">Acme Software Solutions</a>
                <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarResponsive">
                  <span class="navbar-toggler-icon"></span>
                </button>
              </div>
            </nav>
            <div class="container">
                <div class="jumbotron mt-5">
                    <h1 class="display-4">Innovative Solutions for Modern Businesses</h1>
                    <p class="lead">At Acme Software Solutions, we provide cutting-edge software to streamline your operations.</p>
                    <hr class="my-4">
                    <p>Our team of experts is dedicated to delivering custom solutions tailored to your needs.</p>
                </div>
                <h2>Upload Your Profile</h2>
                <p>Please upload your profile information in XML format.</p>
                <form method="POST" action="/upload">
                    <div class="form-group">
                        <label for="xmlInput">XML Input</label>
                        <textarea class="form-control" id="xmlInput" name="xmlInput" rows="10"></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary">Upload Profile</button>
                </form>
            </div>
            <!-- Bootstrap JS dependencies -->
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.0/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
    ''')

@app.route('/upload', methods=['POST'])
def upload():
    xml_data = request.form['xmlInput']
    try:
        # Parse the XML data with external entities enabled (vulnerable to XXE)
        parser = etree.XMLParser(resolve_entities=True)
        root = etree.fromstring(xml_data.encode(), parser)
        # Process the XML data
        elements = []
        found_secret = False
        secret_message = ''
        for elem in root.iter():
            elements.append((elem.tag, elem.text))
            if elem.tag == 'secret':
                found_secret = True
                secret_message = elem.text
        return render_template_string('''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Acme Software Solutions - Profile Uploaded</title>
                <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
            </head>
            <body>
                <div class="container">
                    <h1 class="mt-5">Profile Uploaded Successfully</h1>
                    {% if found_secret %}
                        <div class="alert alert-success" role="alert">
                            {{ secret_message }}
                        </div>
                    {% endif %}
                    <p class="lead">Your profile has been uploaded with the following details:</p>
                    <ul>
                        {% for tag, text in elements %}
                            <li><strong>{{ tag }}:</strong> {{ text }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </body>
            </html>
        ''', elements=elements, found_secret=found_secret, secret_message=secret_message)
    except Exception as e:
        return render_template_string('''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Error</title>
                <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
            </head>
            <body>
                <div class="container">
                    <h1 class="mt-5 text-danger">An Error Occurred</h1>
                    <p class="lead">There was an error processing your XML data.</p>
                </div>
            </body>
            </html>
        '''), 400
if __name__ == '__main__':
    app.run(debug=True, port=5000)