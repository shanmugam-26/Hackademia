from flask import Flask, render_template_string, request, redirect, url_for
app = Flask(__name__)

# Include Bootstrap CSS framework
bootstrap_css = '''
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
'''

# Main page template
main_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Institute of Technology</title>
    {{ bootstrap_css|safe }}
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">Global Institute of Technology</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
</nav>
<div class="container">
    <div class="jumbotron mt-4">
        <h1 class="display-4">Welcome to GIT!</h1>
        <p class="lead">Leading the way in technological education.</p>
        <hr class="my-4">
        <p>Sign in to access your personalized student portal.</p>
        <form action="/login" method="get">
            <div class="form-group">
                <label for="email">Student Email</label>
                <input type="email" class="form-control" id="email" name="email" placeholder="Enter your student email">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" class="form-control" id="password" name="password" placeholder="Enter your password">
            </div>
            <button type="submit" class="btn btn-primary">Access Portal</button>
        </form>
    </div>
</div>
</body>
</html>
'''

# Congratulations page template
congrats_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    {{ bootstrap_css|safe }}
</head>
<body>
<div class="container text-center">
    <div class="alert alert-success mt-5">
        <h1 class="alert-heading">Congratulations!</h1>
        <p>You have successfully exploited the vulnerability.</p>
    </div>
</div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(main_page, bootstrap_css=bootstrap_css)

@app.route('/login', methods=['GET'])
def login():
    email = request.args.get('email')
    password = request.args.get('password')
    # Insecure Communication: Credentials are sent via GET over HTTP
    # Normally, credentials should be sent via POST over HTTPS
    if email and password:
        # This is just a placeholder for authentication logic
        return redirect(url_for('congratulations'))
    else:
        return redirect(url_for('home'))

@app.route('/congratulations')
def congratulations():
    return render_template_string(congrats_page, bootstrap_css=bootstrap_css)
if __name__ == '__main__':
        app.run(debug=True)