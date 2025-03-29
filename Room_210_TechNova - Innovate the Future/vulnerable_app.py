from flask import Flask, render_template_string, request, send_file, abort
import os

app = Flask(__name__)

# Create 'files' directory and sample files if they don't exist
if not os.path.exists('files'):
    os.makedirs('files')

with open('files/whitepaper1.txt', 'w') as f:
    f.write('This is TechNova Whitepaper 1.')

with open('files/whitepaper2.txt', 'w') as f:
    f.write('This is TechNova Whitepaper 2.')

# Create a secret file outside the 'files' directory
with open('secret.txt', 'w') as f:
    f.write('Congratulations! You have found the secret file.')

home_html = '''
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>TechNova - Innovate the Future</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
  </head>
  <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="#">TechNova</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"        aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
    </nav>
    <div class="container mt-5">
      <h1>Welcome to TechNova</h1>
      <p>Your partner in innovative tech solutions.</p>
      <p>Download our latest whitepapers:</p>
      <form action="/download" method="get">
        <div class="form-group">
          <label for="filename">File Name:</label>
          <input type="text" class="form-control" id="filename" name="filename" placeholder="Enter filename">
        </div>
        <button type="submit" class="btn btn-primary">Download</button>
      </form>
    </div>
  </body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_html)

@app.route('/download')
def download():
    filename = request.args.get('filename')
    if not filename:
        return 'No filename provided', 400

    # Vulnerable code: does not sanitize user input
    file_path = os.path.join('files', filename)

    if not os.path.exists(file_path):
        return 'File not found', 404

    # If the secret file is accessed, congratulate the user
    if os.path.abspath(file_path) == os.path.abspath('secret.txt'):
        return 'Congratulations! You have exploited the directory traversal vulnerability.'

    return send_file(file_path, as_attachment=True)
if __name__ == '__main__':
      app.run(debug=True, port=5000)