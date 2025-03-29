from flask import Flask, render_template_string, request, send_file, abort
import os

app = Flask(__name__)

# Simulating a list of documents for download
DOCS_DIR = os.path.abspath("documents")
os.makedirs(DOCS_DIR, exist_ok=True)
with open(os.path.join(DOCS_DIR, "company_overview.pdf"), "w") as f:
    f.write("Company Overview Document")
with open(os.path.join(DOCS_DIR, "product_specs.pdf"), "w") as f:
    f.write("Product Specifications Document")

# HTML template with modern CSS framework (Bootstrap)
html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Techify Solutions - Innovating the Future</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">Techify Solutions</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" 
          aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
</nav>
<div class="container">
    <div class="mt-5">
        <h1>Welcome to Techify Solutions</h1>
        <p>At Techify Solutions, we are committed to delivering innovative tech products that revolutionize the industry.</p>
        <h3 class="mt-4">Download Our Documents</h3>
        <form action="/download" method="get" class="form-inline">
            <div class="form-group mb-2">
                <label for="filename" class="sr-only">Filename</label>
                <input type="text" class="form-control" id="filename" name="filename" placeholder="Enter filename">
            </div>
            <button type="submit" class="btn btn-primary mb-2">Download</button>
        </form>
    </div>
</div>
<!-- Bootstrap JS -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
{% if message %}
<script>alert("{{ message }}");</script>
{% endif %}
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(html_template)

@app.route('/download')
def download():
    filename = request.args.get('filename', '')
    filepath = os.path.join(DOCS_DIR, filename)

    # Vulnerability: No proper sanitization of the filename (Directory Traversal)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        # Hidden Congratulations prompt for successful exploitation
        if '../' in filename or '..\\' in filename:
            message = "Congratulations! You've discovered the hidden message."
            return render_template_string(html_template, message=message)
        abort(404)
if __name__ == '__main__':
            app.run(debug=True, host='0.0.0.0', port=5000)