from flask import Flask, request, render_template_string, send_file, abort
import os

app = Flask(__name__)

# Configuration for file uploads
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'files')

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Create a sample file to download
sample_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'sample.txt')
with open(sample_file_path, 'w') as f:
    f.write('This is the official company brochure of Acme Software Solutions.')

# Create a configuration file with a secret key
secret_key = 'SuperSecretKey12345'
config_file_path = os.path.join(os.getcwd(), 'config.txt')
with open(config_file_path, 'w') as f:
    f.write(f'SECRET_KEY={secret_key}')

# Route for the home page
@app.route('/')
def index():
    html = '''
    <!doctype html>
    <html lang="en">
      <head>
        <!-- Meta Tags -->
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <!-- Bootstrap CSS -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
        <title>Acme Software Solutions</title>
      </head>
      <body>
        <!-- Navigation Bar -->
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
          <div class="container-fluid">
            <a class="navbar-brand" href="/">Acme Software Solutions</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarColor01">
              <span class="navbar-toggler-icon"></span>
            </button>
          </div>
        </nav>
        <!-- Main Content -->
        <div class="container mt-5">
          <h1>Welcome to Acme Software Solutions</h1>
          <p>Your trusted partner in innovative software development.</p>
          <p>Download our company brochure <a href="/download?file=sample.txt">here</a>.</p>
        </div>
        <!-- Bootstrap JS -->
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
      </body>
    </html>
    '''
    return render_template_string(html)

# Vulnerable download endpoint
@app.route('/download')
def download():
    filename = request.args.get('file', '')
    if not filename:
        abort(404)
    # Intentionally vulnerable to directory traversal
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    try:
        return send_file(filepath, as_attachment=True)
    except Exception:
        return "Error processing your request.", 500

# Endpoint to verify the secret key
@app.route('/flag')
def flag():
    key = request.args.get('key', '')
    # Read SECRET_KEY from config.txt
    config_file_path = os.path.join(os.getcwd(), 'config.txt')
    with open(config_file_path, 'r') as f:
        content = f.read()
    stored_key = content.strip().split('=')[1]
    if key == stored_key:
        return '''
        <!doctype html>
        <html lang="en">
          <head>
            <meta charset="utf-8">
            <title>Congratulations</title>
          </head>
          <body>
            <h1>Congratulations!</h1>
            <p>You have successfully exploited the vulnerability.</p>
          </body>
        </html>
        '''
    else:
        return "Invalid key.", 403

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)