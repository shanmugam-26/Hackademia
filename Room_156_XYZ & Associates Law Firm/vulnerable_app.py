from flask import Flask, request, render_template_string
import os

# Create 'documents' directory if it doesn't exist
if not os.path.exists('documents'):
    os.makedirs('documents')

# Create sample files in 'documents' directory
with open('documents/legal_notice.txt', 'w') as f:
    f.write('This is a legal notice.')

with open('documents/privacy_policy.txt', 'w') as f:
    f.write('This is the privacy policy.')

# Create a secret file outside 'documents' directory
with open('secret.txt', 'w') as f:
    f.write('Congratulations! You have found the secret file.')

app = Flask(__name__)

home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>XYZ & Associates Law Firm</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1>Welcome to XYZ & Associates Law Firm</h1>
        <p>At XYZ & Associates, we are committed to providing exceptional legal services for businesses and individuals.</p>
        <a href="/documents" class="btn btn-primary">Client Documents</a>
    </div>
</body>
</html>
'''

documents_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Client Documents - XYZ & Associates Law Firm</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1>Client Documents</h1>
        <ul>
            {% for file in files %}
            <li><a href="/document?file={{ file }}">{{ file }}</a></li>
            {% endfor %}
        </ul>
        <form action="/document" method="get">
            <div class="mb-3">
                <label for="file" class="form-label">View Document</label>
                <input type="text" class="form-control" id="file" name="file" placeholder="Enter filename">
            </div>
            <button type="submit" class="btn btn-primary">View</button>
        </form>
    </div>
</body>
</html>
'''

document_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>View Document - XYZ & Associates Law Firm</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h1>Document Contents</h1>
        <pre>{{ content }}</pre>
        <a href="/documents" class="btn btn-secondary">Back to Documents</a>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/documents')
def documents():
    # List the files in the 'documents' directory
    files = os.listdir('documents')
    return render_template_string(documents_template, files=files)

@app.route('/document')
def document():
    file = request.args.get('file', '')
    try:
        # Vulnerable code: does not sanitize file path
        filepath = os.path.join('documents', file)
        with open(filepath, 'r') as f:
            content = f.read()
        return render_template_string(document_template, content=content)
    except Exception as e:
        return 'Error: File not found or inaccessible.'
if __name__ == '__main__':
        app.run(debug=True, port=5000)