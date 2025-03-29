from flask import Flask, request, render_template_string, make_response

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    name = request.form.get('name', '')
    challenge_completed = False
    if 'challenge' in request.cookies:
        if request.cookies.get('challenge') == 'completed':
            challenge_completed = True

    html_content = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Aid Foundation</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="#">Global Aid Foundation</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item"><a class="nav-link" href="#mission">Mission</a></li>
                <li class="nav-item"><a class="nav-link" href="#programs">Programs</a></li>
                <li class="nav-item"><a class="nav-link" href="#contact">Contact Us</a></li>
            </ul>
        </div>
    </nav>
    <div class="container mt-5">
        <h1>Welcome to Global Aid Foundation</h1>
        <p>Our mission is to provide aid to communities in need around the world.</p>

        {% if challenge_completed %}
            <div class="alert alert-success" role="alert">
                Congratulations! You have successfully completed the challenge.
            </div>
        {% endif %}

        <form method="POST">
            <div class="form-group">
                <label for="name">Subscribe to our newsletter:</label>
                <input type="text" class="form-control" id="name" name="name" placeholder="Enter your name">
            </div>
            <button type="submit" class="btn btn-primary">Subscribe</button>
        </form>
        <br>
        <p>Your subscription confirmation: ''' + name + '''</p>
    </div>
    <footer class="bg-light text-center mt-5 p-3">
        &copy; 2023 Global Aid Foundation
    </footer>
</body>
</html>
    '''
    response = make_response(render_template_string(html_content, challenge_completed=challenge_completed))
    return response
if __name__ == '__main__':
        app.run(debug=True)