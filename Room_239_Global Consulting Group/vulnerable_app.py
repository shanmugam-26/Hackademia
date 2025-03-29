from flask import Flask, request, render_template_string
from lxml import etree

app = Flask(__name__)

index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Consulting Group</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
  <a class="navbar-brand" href="#">Global Consulting Group</a>
</nav>
<div class="container mt-5">
    <h1>Welcome to Global Consulting Group</h1>
    <p>We provide world-class consulting services in strategy, operations, and technology.</p>
    <h3>Submit Your Project Details</h3>
    <form action="/upload" method="post">
      <div class="mb-3">
        <label for="xmlInput" class="form-label">Project Details (XML format):</label>
        <textarea class="form-control" id="xmlInput" name="xml" rows="10" placeholder="Enter your project details in XML format"></textarea>
      </div>
      <button type="submit" class="btn btn-primary">Submit</button>
    </form>
</div>
<!-- Bootstrap JS and dependencies -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

result_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Submission Result</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        pre {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
<div class="container mt-5">
    {% if error %}
    <div class="alert alert-danger" role="alert">
      {{ error }}
    </div>
    {% else %}
    <h1>Thank you for your submission!</h1>
    <p>Your project details have been received and are being reviewed by our consultants.</p>
    <h3>Processed Details:</h3>
    <pre>{{ result }}</pre>
    {% if congratulations %}
    <div class="alert alert-success mt-3" role="alert">
        Congratulations! You have successfully exploited the vulnerability.
    </div>
    {% endif %}
    {% endif %}
</div>
<!-- Bootstrap JS and dependencies -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(index_html)

@app.route('/upload', methods=['POST'])
def upload():
    xml_data = request.form['xml']
    try:
        parser = etree.XMLParser(load_dtd=True, no_network=False)
        tree = etree.fromstring(xml_data.encode('utf-8'), parser)
        result = etree.tostring(tree, pretty_print=True).decode('utf-8')
        congratulations = False
        if "Congratulations" in result or "congratulations" in result:
            congratulations = True
        return render_template_string(result_html, result=result, congratulations=congratulations)
    except Exception as e:
        error = f'Error processing XML: {str(e)}'
        return render_template_string(result_html, error=error)
if __name__ == '__main__':
        app.run(debug=True)