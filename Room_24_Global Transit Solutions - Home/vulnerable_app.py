from flask import Flask, request, render_template_string
import lxml.etree as ET

app = Flask(__name__)

# Write the secret file
secret_file = 'secret.txt'
secret_content = 'Congratulations! You have found the secret!'
with open(secret_file, 'w') as f:
    f.write(secret_content)

# Home page
@app.route('/')
def index():
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>Global Transit Solutions - Home</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }
            .header {
                background-color: #003366;
                color: #fff;
                padding: 20px;
                text-align: center;
            }
            .container {
                padding: 20px;
            }
            h1 {
                color: #003366;
            }
            form {
                margin-top: 20px;
            }
            textarea {
                width: 100%;
                padding: 10px;
                font-size: 16px;
            }
            input[type="submit"] {
                padding: 10px 20px;
                background-color: #003366;
                color: #fff;
                border: none;
                cursor: pointer;
                font-size: 16px;
            }
            input[type="submit"]:hover {
                background-color: #005599;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Global Transit Solutions</h1>
            <p>Your partner in efficient and reliable transportation services.</p>
        </div>
        <div class="container">
            <h2>Schedule Your Trip</h2>
            <p>Please submit your trip details in XML format below:</p>
            <form action="/process" method="post">
                <textarea name="xml_data" rows="15"></textarea><br>
                <input type="submit" value="Submit Trip">
            </form>
        </div>
    </body>
    </html>
    ''')

# Process the XML data
@app.route('/process', methods=['POST'])
def process():
    xml_data = request.form['xml_data']
    try:
        parser = ET.XMLParser(resolve_entities=True)
        root = ET.fromstring(xml_data.encode('utf-8'), parser=parser)
        # Process the XML data and extract information
        # For simplicity, we can display the parsed XML content
        result = ET.tostring(root, pretty_print=True).decode()
        # Check if the secret content is in the result
        if secret_content in result:
            message = 'Congratulations! You have successfully exploited the vulnerability.'
        else:
            message = 'Thank you for submitting your trip details. We will process them shortly.'
        return render_template_string('''
        <!doctype html>
        <html>
        <head>
            <title>Global Transit Solutions - Processing Result</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 0;
                }
                .header {
                    background-color: #003366;
                    color: #fff;
                    padding: 20px;
                    text-align: center;
                }
                .container {
                    padding: 20px;
                }
                h1 {
                    color: #003366;
                }
                pre {
                    background-color: #fff;
                    padding: 10px;
                    border: 1px solid #ddd;
                    overflow-x: auto;
                }
                a {
                    display: inline-block;
                    margin-top: 20px;
                    padding: 10px 20px;
                    background-color: #003366;
                    color: #fff;
                    text-decoration: none;
                }
                a:hover {
                    background-color: #005599;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Global Transit Solutions</h1>
            </div>
            <div class="container">
                <h2>Processing Result</h2>
                <pre>{{ result }}</pre>
                <p>{{ message }}</p>
                <a href="/">Submit Another Trip</a>
            </div>
        </body>
        </html>
        ''', result=result, message=message)
    except Exception as e:
        return 'Error processing XML data: ' + str(e)

if __name__ == '__main__':
    app.run(debug=True)