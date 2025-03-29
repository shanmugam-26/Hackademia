from flask import Flask, render_template_string, request, redirect
app = Flask(__name__)

# Base HTML template with Bootstrap 4
base_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>La Petite Cuisine</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="/">La Petite Cuisine</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav"      aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
</nav>
<div class="container">
    {% block content %}{% endblock %}
</div>
</body>
</html>
'''

# Home page template
home_template = '''
{% extends "base.html" %}
{% block content %}
<div class="jumbotron mt-4">
  <h1 class="display-4">Bienvenue à La Petite Cuisine!</h1>
  <p class="lead">Experience the finest French dining right here in your city.</p>
  <hr class="my-4">
  <p>Explore our exquisite menu or contact us for reservations.</p>
  <a class="btn btn-primary btn-lg" href="/menu" role="button">View Menu</a>
  <a class="btn btn-secondary btn-lg" href="/contact" role="button">Contact Us</a>
</div>
{% endblock %}
'''

# Menu page template
menu_template = '''
{% extends "base.html" %}
{% block content %}
<h2>Our Menu</h2>
<p>Discover our selection of gourmet dishes crafted with love and the freshest ingredients.</p>
<div class="row">
  <div class="col-md-4">
    <h4>Entrées</h4>
    <ul>
      <li>French Onion Soup</li>
      <li>Escargots de Bourgogne</li>
    </ul>
  </div>
  <div class="col-md-4">
    <h4>Main Courses</h4>
    <ul>
      <li>Boeuf Bourguignon</li>
      <li>Coq au Vin</li>
    </ul>
  </div>
  <div class="col-md-4">
    <h4>Desserts</h4>
    <ul>
      <li>Crème Brûlée</li>
      <li>Tarte Tatin</li>
    </ul>
  </div>
</div>
{% endblock %}
'''

# Contact page template with a redirect link
contact_template = '''
{% extends "base.html" %}
{% block content %}
<h2>Contact Us</h2>
<p>We'd love to hear from you! Please reach out with any inquiries or reservations.</p>
<p>Email: info@lapetitecuisine.com</p>
<p>Phone: (123) 456-7890</p>
<p>Follow us on social media:</p>
<ul>
  <li><a href="/redirect?url=https://www.facebook.com/lapetitecuisine">Facebook</a></li>
  <li><a href="/redirect?url=https://www.twitter.com/lapetitecuisine">Twitter</a></li>
</ul>
{% endblock %}
'''

# Secret page template
secret_template = '''
{% extends "base.html" %}
{% block content %}
<div class="mt-4 text-center">
  <h2>Congratulations!</h2>
  <p class="lead">You have successfully exploited the unvalidated redirect vulnerability!</p>
  <img src="https://media.giphy.com/media/111ebonMs90YLu/giphy.gif" alt="Congratulations" class="img-fluid">
</div>
{% endblock %}
'''

@app.route('/')
def home():
    return render_template_string(home_template, **{'base.html': base_template})

@app.route('/menu')
def menu():
    return render_template_string(menu_template, **{'base.html': base_template})

@app.route('/contact')
def contact():
    return render_template_string(contact_template, **{'base.html': base_template})

@app.route('/redirect')
def unsafe_redirect():
    url = request.args.get('url')
    if url:
        return redirect(url)
    else:
        return "No url provided to redirect.", 400

@app.route('/secret')
def secret():
    return render_template_string(secret_template, **{'base.html': base_template})
if __name__ == '__main__':
      app.run(debug=True, port=45000)