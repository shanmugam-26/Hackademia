from flask import Flask, request, render_template_string

app = Flask(__name__)

template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Wanderlust Travel Agency</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Welcome to Wanderlust Travel Agency</h1>
        <p class="lead">Discover your next adventure with us! Search for exciting destinations below.</p>
        <form action="/search" method="get">
            <div class="form-group">
                <input type="text" name="destination" class="form-control" placeholder="Enter your dream destination">
            </div>
            <button type="submit" class="btn btn-primary">Search</button>
        </form>
        {% if destination %}
            <h2 class="mt-5">Results for "{{ destination | safe }}"</h2>
            <p>Sorry, no results found for "{{ destination | safe }}". Please try another destination.</p>
        {% endif %}
    </div>
    <script>
    if (typeof window.xssVulnerabilityExploited !== 'undefined' && window.xssVulnerabilityExploited === true) {
        alert('Congratulations! You have successfully exploited the XSS vulnerability.');
    }
    </script>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return render_template_string(template)

@app.route('/search', methods=['GET'])
def search():
    destination = request.args.get('destination')
    # Intentionally vulnerable to XSS
    return render_template_string(template, destination=destination)
if __name__ == '__main__':
        app.jinja_env.autoescape = False
        app.run(debug=True, port=5000)