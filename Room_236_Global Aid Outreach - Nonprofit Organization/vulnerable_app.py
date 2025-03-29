from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Aid Outreach - Nonprofit Organization</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body {
                background-color: #f8f9fa;
            }
            .hero {
                background-image: url('https://via.placeholder.com/1200x400');
                background-size: cover;
                background-position: center;
                color: white;
                text-align: center;
                padding: 150px 0;
            }
            .hero h1 {
                font-size: 4em;
                font-weight: bold;
            }
            .content {
                margin-top: 30px;
            }
            footer {
                background-color: #343a40;
                color: white;
                padding: 20px 0;
                text-align: center;
                margin-top: 30px;
            }
        </style>
    </head>
    <body>
    <nav class="navbar navbar-expand-md navbar-dark bg-dark">
      <a class="navbar-brand" href="#">Global Aid Outreach</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav ml-auto">
          <li class="nav-item active">
            <a class="nav-link" href="#">Home</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="#">Our Work</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="#">Get Involved</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="#">Donate</a>
          </li>
        </ul>
      </div>
    </nav>
    <div class="hero">
        <h1>Making the World a Better Place</h1>
        <p>Together we can make a difference</p>
    </div>
    <div class="container content">
        <h2>About Us</h2>
        <p>Global Aid Outreach is dedicated to providing support to communities in need around the world. Our mission is to bring hope, resources, and sustainable solutions to those facing challenges.</p>
        <h2>Our Partners</h2>
        <p>We collaborate with a network of partners to maximize our impact. Learn more about them below.</p>
        <form action="/fetch" method="post">
            <div class="form-group">
                <label for="url">Partner Information:</label>
                <input type="text" class="form-control" id="url" name="url" placeholder="Enter partner URL">
            </div>
            <button type="submit" class="btn btn-primary">Visit Partner Site</button>
        </form>
    </div>
    <footer>
        <p>&copy; 2023 Global Aid Outreach. All rights reserved.</p>
    </footer>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route("/fetch", methods=["POST"])
def fetch():
    url = request.form.get('url')
    try:
        response = requests.get(url)
        content = response.text
        if 'CONGRATULATIONS' in content or 'Congratulations' in content or 'congratulations' in content:
            message = '''
            <div class="alert alert-success" role="alert">
              <h4 class="alert-heading">Congratulations!</h4>
              <p>You have successfully exploited the vulnerability.</p>
            </div>
            '''
        else:
            message = '<h2>Content from URL:</h2><pre>{}</pre>'.format(content)
    except Exception as e:
        message = '<div class="alert alert-danger" role="alert"><h4 class="alert-heading">Error:</h4><p>Unable to fetch the URL.</p><hr><p class="mb-0">{}</p></div>'.format(e)
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Aid Outreach - Partner Information</title>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body {
                background-color: #f8f9fa;
            }
            .content {
                margin-top: 30px;
            }
            footer {
                background-color: #343a40;
                color: white;
                padding: 20px 0;
                text-align: center;
                margin-top: 30px;
            }
        </style>
    </head>
    <body>
    <nav class="navbar navbar-expand-md navbar-dark bg-dark">
      <a class="navbar-brand" href="#">Global Aid Outreach</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
        <span class="navbar-toggler-icon"></span>
      </button>
    </nav>
    <div class="container content">
        {}
    </div>
    <footer>
        <p>&copy; 2023 Global Aid Outreach. All rights reserved.</p>
    </footer>
    </body>
    </html>
    '''.format(message)
    return render_template_string(html)

if __name__ == "__main__":
    app.run(debug=True)