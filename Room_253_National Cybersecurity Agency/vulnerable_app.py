from flask import Flask, render_template_string
app = Flask(__name__)

# Misconfiguration: Secret key is hard-coded and weak
app.secret_key = '1234'

# Misconfiguration: Debug mode is enabled
app.config['DEBUG'] = True

@app.route('/')
def index():
    # Use modern CSS frameworks (Bootstrap)
    html = '''
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>National Cybersecurity Agency</title>
        <!-- Bootstrap CSS -->
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
      </head>
      <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
          <a class="navbar-brand" href="#">NCA</a>
          <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
          </button>
        </nav>
        <div class="container mt-5">
          <h1>Welcome to the National Cybersecurity Agency</h1>
          <p class="lead">Protecting the nation's cyberspace.</p>
          <p>Our mission is to secure and defend national infrastructure against cyber threats.</p>
        </div>
        <!-- Bootstrap JS and dependencies -->
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
      </body>
    </html>
    '''
    return render_template_string(html)

# Intentional misconfiguration: Expose configuration details
@app.route('/config')
def config():
    return '''
    <h2>Congratulations!</h2>
    <p>You have discovered the misconfiguration.</p>
    '''

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)