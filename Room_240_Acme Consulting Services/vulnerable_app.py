from flask import Flask, render_template_string, request
import os

app = Flask(__name__)

# The HTML for the main page
html_main = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Acme Consulting Services</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">Acme Consulting</a>
</nav>

<div class="container mt-5">
  <h1>Welcome to Acme Consulting Services</h1>
  <p>We offer top-tier consulting services for businesses worldwide.</p>
  <form method="post" action="/process">
    <div class="mb-3">
      <label for="request" class="form-label">Submit your project request in XML format:</label>
      <textarea class="form-control" id="request" name="request" rows="5" placeholder="&lt;?xml version=&quot;1.0&quot;?&gt;&#10;&lt;request&gt;&#10;  &lt;project&gt;Project Name&lt;/project&gt;&#10;  &lt;description&gt;Project Description&lt;/description&gt;&#10;&lt;/request&gt;"></textarea>
    </div>
    <button type="submit" class="btn btn-primary">Submit Request</button>
  </form>
</div>
</body>
</html>
'''

# The route for the main page
@app.route('/', methods=['GET'])
def index():
    return render_template_string(html_main)

# Import lxml for XML parsing
from lxml import etree

@app.route('/process', methods=['POST'])
def process():
    xml_data = request.form.get('request')
    if xml_data:
        try:
            # Parse the XML data (vulnerable to XXE)
            tree = etree.fromstring(xml_data)
            project = tree.find('project').text
            description = tree.find('description').text
            response = f'''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Submission Received</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body>
            <div class="container mt-5">
                <h2>Thank you for your submission!</h2>
                <p><strong>Project:</strong> {project}</p>
                <p><strong>Description:</strong> {description}</p>
            '''

            # Check for XXE exploitation
            if 'Congratulations' in project or 'Congratulations' in description:
                response += '''
                <div class="alert alert-success mt-3" role="alert">
                    Congratulations, you have found the vulnerability!
                </div>
                '''

            response += '''
            </div>
            </body>
            </html>
            '''
        except Exception as e:
            response = f'''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Error</title>
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body>
            <div class="container mt-5">
                <h2>Error processing your request</h2>
                <pre>{e}</pre>
            </div>
            </body>
            </html>
            '''
    else:
        response = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>No Data</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
        <div class="container mt-5">
            <h2>No data received.</h2>
        </div>
        </body>
        </html>
        '''
    return response

if __name__ == '__main__':
        app.run(debug=True)