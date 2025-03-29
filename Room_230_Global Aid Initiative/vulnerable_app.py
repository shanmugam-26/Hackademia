from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

# HTML template with modern CSS framework (Bootstrap)
html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Aid Initiative</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
    /* Additional custom styles */
    body {
        padding-top: 5rem;
    }
    .starter-template {
        padding: 3rem 1.5rem;
        text-align: center;
    }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
  <a class="navbar-brand" href="#">Global Aid Initiative</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"       aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
</nav>

<main role="main" class="container">

  <div class="starter-template">
    <h1>Welcome to Global Aid Initiative</h1>
    <p class="lead">Our mission is to provide support and resources to communities in need across the globe.<br>We believe in making the world a better place for everyone.</p>
  </div>

</main>

<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/[email protected]/dist/umd/popper.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.min.js"></script>

<!--
Note: For development use only
Secret API Key: FLAG{S3ns1t1v3_D4t4_Exp0s3d}
-->

</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(html_template)

@app.route('/submit_key', methods=['GET', 'POST'])
def submit_key():
    if request.method == 'POST':
        key = request.form.get('key')
        if key == 'FLAG{S3ns1t1v3_D4t4_Exp0s3d}':
            return redirect(url_for('congratulations'))
        else:
            return render_template_string('''
            <h1>Invalid Key</h1>
            <p>The key you submitted is incorrect.</p>
            <a href="/">Go back</a>
            ''')
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Submit API Key - Global Aid Initiative</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
        <style>
        body {
            padding-top: 5rem;
        }
        .form-container {
            padding: 3rem 1.5rem;
            max-width: 500px;
            margin: auto;
        }
        </style>
    </head>
    <body>
    <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
      <a class="navbar-brand" href="#">Global Aid Initiative</a>
    </nav>
    <div class="form-container">
        <h2>Enter API Key</h2>
        <form method="post">
            <div class="form-group">
                <label for="key">API Key:</label>
                <input type="text" name="key" id="key" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
    </div>
    </body>
    </html>
    ''')

@app.route('/congratulations')
def congratulations():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Congratulations!</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
        <style>
        body {
            padding-top: 5rem;
            text-align: center;
        }
        .congrats-container {
            padding: 3rem 1.5rem;
        }
        </style>
    </head>
    <body>
    <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
      <a class="navbar-brand" href="#">Global Aid Initiative</a>
    </nav>
    <div class="congrats-container">
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the sensitive data exposure vulnerability.</p>
    </div>
    </body>
    </html>
    '''
if __name__ == '__main__':
        app.run(debug=True)