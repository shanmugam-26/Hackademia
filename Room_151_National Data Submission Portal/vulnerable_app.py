from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

# HTML template for the main page
html_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>National Data Submission Portal</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
        .header { background-color: #003366; color: #ffffff; padding: 20px; text-align: center; }
        .container { padding: 20px; margin: auto; width: 50%; background-color: #ffffff; }
        input[type=text], textarea { width: 100%; padding: 12px; }
        input[type=submit] { background-color: #003366; color: white; padding: 12px; border: none; cursor: pointer; }
        input[type=submit]:hover { background-color: #002244; }
    </style>
</head>
<body>
    <div class="header">
        <h1>National Data Submission Portal</h1>
    </div>
    <div class="container">
        <h2>Submit Your Data</h2>
        <form method="post" action="/submit">
            <label for="xml_data">XML Data:</label><br/>
            <textarea id="xml_data" name="xml_data" rows="10"></textarea><br/><br/>
            <input type="submit" value="Submit XML">
        </form>
    </div>
    {% if result %}
    <div class="container">
        <h2>Result</h2>
        <p>{{ result }}</p>
    </div>
    {% endif %}
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return render_template_string(html_template)

@app.route('/submit', methods=['POST'])
def submit_xml():
    xml_data = request.form['xml_data']
    try:
        parser = etree.XMLParser(resolve_entities=True)
        root = etree.fromstring(xml_data, parser)
        result = "XML data processed successfully."
    except Exception as e:
        result = "Error processing XML data: " + str(e)
    # Check for successful exploitation
    if 'congratulations' in xml_data.lower():
        result = "Congratulations! You've successfully exploited the vulnerability."
    return render_template_string(html_template, result=result)

if __name__ == '__main__':
    app.run(debug=True)