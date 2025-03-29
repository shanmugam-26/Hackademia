from flask import Flask, request, render_template_string
import lxml.etree as ET

app = Flask(__name__)

# Home page HTML with Bootstrap CSS framework
home_page = '''
<!doctype html>
<html lang="en">
<head>
    <!-- Using Bootstrap CSS framework -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>National Data Submission Portal</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1 class="mt-5">National Data Submission Portal</h1>
        <p class="lead">Welcome to the official government portal for submitting sensitive data.</p>
        <form method="post" action="/submit" enctype="multipart/form-data">
            <div class="mb-3">
                <label for="xmlfile" class="form-label">Upload your XML file</label>
                <input class="form-control" type="file" id="xmlfile" name="xmlfile">
            </div>
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return home_page

@app.route('/submit', methods=['POST'])
def submit():
    xmlfile = request.files.get('xmlfile')
    if xmlfile:
        try:
            xml_content = xmlfile.read()
            # Parse XML without disabling external entity references (XXE vulnerability)
            parser = ET.XMLParser()
            tree = ET.fromstring(xml_content, parser)
            # Process the XML data (dummy processing)
            result = ET.tostring(tree)
            # Check for XXE exploitation (e.g., presence of a specific tag or content)
            if b'congratulations' in result.lower():
                return render_template_string('''
                <h2>Congratulations!</h2>
                <p>You have successfully exploited the XXE vulnerability!</p>
                ''')
            else:
                return render_template_string('''
                <h2>Data Processed Successfully</h2>
                <p>Your data has been submitted.</p>
                ''')
        except Exception as e:
            return render_template_string('''
            <h2>Error</h2>
            <p>There was an error processing your XML file.</p>
            ''')
    else:
        return render_template_string('''
        <h2>No File Uploaded</h2>
        <p>Please upload an XML file.</p>
        ''')
if __name__ == '__main__':
            app.run(debug=True, host='0.0.0.0', port=5000)