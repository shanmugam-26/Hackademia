from flask import Flask, request, render_template_string, redirect, url_for, flash
import lxml.etree as ET
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

index_html = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>TechNova Solutions</title>
  <style>
    body { font-family: Arial, sans-serif; background-color: #f4f6f9; margin: 0; padding: 0; }
    .header { background-color: #2c3e50; padding: 20px; color: white; text-align: center; }
    .container { padding: 50px; max-width: 800px; margin: auto; background-color: white; }
    h1 { color: #2c3e50; }
    input[type="text"], textarea { width: 100%; padding: 10px; margin: 5px 0 20px 0; border: 1px solid #ccc; }
    input[type="submit"] { background-color: #2c3e50; color: white; padding: 10px 20px; border: none; cursor: pointer; }
    input[type="submit"]:hover { background-color: #34495e; }
    .footer { background-color: #2c3e50; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
    .message { color: green; }
  </style>
</head>
<body>
  <div class="header">
    <h1>TechNova Solutions</h1>
    <p>Innovating the Future</p>
  </div>
  <div class="container">
    <h2>Welcome to TechNova Solutions</h2>
    <p>At TechNova Solutions, we are at the forefront of technological innovation, delivering cutting-edge solutions to our global clientele.</p>
    <h3>Contact Us</h3>
    <form action="{{ url_for('process_xml') }}" method="post">
      <label for="xml_input">Send us your feedback in XML format:</label><br>
      <textarea id="xml_input" name="xml_input" rows="10" required></textarea><br>
      <input type="submit" value="Submit">
    </form>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="message">
          {% for message in messages %}
            <p>{{ message }}</p>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}
  </div>
  <div class="footer">
    &copy; 2023 TechNova Solutions
  </div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def home():
    return render_template_string(index_html)

@app.route('/process_xml', methods=['POST'])
def process_xml():
    xml_input = request.form.get('xml_input')
    try:
        parser = ET.XMLParser()
        tree = ET.fromstring(xml_input.encode('utf-8'), parser)
        response = tree.findtext('.//message')
        if response:
            flash(f"Thank you for your message: {response}")
        else:
            flash("Your XML was processed successfully.")
    except ET.ParseError as e:
        flash("There was an error parsing your XML.")
    except Exception as e:
        flash("An unexpected error occurred.")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)