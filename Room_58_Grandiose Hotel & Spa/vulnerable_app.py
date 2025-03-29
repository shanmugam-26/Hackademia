from flask import Flask, request, render_template_string, send_file
import os

app = Flask(__name__)

# Create 'files' directory if it doesn't exist
os.makedirs('files', exist_ok=True)

# Create a sample 'brochure.pdf' file
with open('files/brochure.pdf', 'wb') as f:
    f.write(b'%PDF-1.4\n% Sample PDF content')

# Create a secret file in another directory
os.makedirs('secret', exist_ok=True)
with open('secret/flag.txt', 'w') as f:
    f.write('Congratulations! You have found the secret file.')

home_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grandiose Hotel & Spa</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f4f4f4;
            margin: 0;
            padding: 0;
        }
        .header {
            background: #333;
            color: white;
            text-align: center;
            padding-top: 150px;
            padding-bottom: 150px;
            font-size: 50px;
        }
        .content {
            padding: 20px;
        }
        .footer {
            background: #333;
            color: white;
            text-align: center;
            padding: 10px;
        }
        .button {
            background: #5A67D8;
            color: white;
            padding: 15px 25px;
            text-decoration: none;
            border-radius: 5px;
        }
        a.button:hover {
            background: #434190;
        }
    </style>
</head>
<body>
    <div class="header">
        Welcome to Grandiose Hotel & Spa
    </div>
    <div class="content">
        <h2>Experience Luxury Like Never Before</h2>
        <p>At Grandiose Hotel & Spa, we offer the finest services to make your stay unforgettable.</p>
        <a href="/download?file=brochure.pdf" class="button">Download Our Brochure</a>
    </div>
    <div class="footer">
        &copy; 2023 Grandiose Hotel & Spa. All rights reserved.
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page_html)

@app.route('/download')
def download():
    filename = request.args.get('file')
    if not filename:
        return "No file specified.", 400

    # Vulnerable code: allows directory traversal
    file_path = os.path.join('files', filename)
    try:
        return send_file(file_path)
    except Exception as e:
        return str(e), 404

if __name__ == '__main__':
    app.run(debug=True)