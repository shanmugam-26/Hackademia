from flask import Flask, request, render_template_string
import os
from lxml import etree

# Create flag.txt file if it doesn't exist
if not os.path.exists('flag.txt'):
    with open('flag.txt', 'w') as f:
        f.write('Congratulations! You have successfully exploited the XXE vulnerability.')

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Fashionscape - Your Gateway to Modern Fashion</title>
    <!-- Include Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container text-center">
        <h1 class="mt-5">Welcome to Fashionscape</h1>
        <p class="lead">Discover the latest trends in fashion and design.</p>
        <a href="/upload" class="btn btn-primary">Create Your Profile</a>
    </div>
</body>
</html>
''')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        xml_data = request.form['xml']
        try:
            # Parse the XML data (this is where the XXE vulnerability is introduced)
            parser = etree.XMLParser(load_dtd=True, no_network=False, resolve_entities=True)
            tree = etree.fromstring(xml_data.encode(), parser)
            # Extract data from XML (e.g., name)
            name = tree.find('name').text
            return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Profile Created</title>
    <!-- Include Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container text-center">
        <h1 class="mt-5">Profile Created for {{ name }}</h1>
        <p class="lead">Thank you for creating your profile!</p>
    </div>
</body>
</html>
''', name=name)
        except Exception as e:
            return 'Error processing XML data: ' + str(e)

    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Create Your Profile</title>
    <!-- Include Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Create Your Profile</h1>
        <p class="lead">Please provide your details in XML format.</p>
        <form method="post">
            <div class="form-group">
                <label for="xml">XML Data:</label>
                <textarea class="form-control" id="xml" name="xml" rows="10"></textarea>
            </div>
            <button type="submit" class="btn btn-primary mt-3">Submit</button>
        </form>
    </div>
</body>
</html>
''')
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)