from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    search_query = request.args.get('q', '')
    html_content = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grand Royal Hotel</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/css/bootstrap.min.css">
    <style>
        body {{
            background-image: url('https://images.unsplash.com/photo-1542314831-068cd1dbfeeb');
            background-size: cover;
            color: #fff;
        }}
        .background-overlay {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
        }}
        .content {{
            position: relative;
            z-index: 2;
        }}
    </style>
</head>
<body>
    <div class="background-overlay"></div>
    <div class="content container">
        <nav class="navbar navbar-expand-lg navbar-dark">
            <a class="navbar-brand" href="#">Grand Royal Hotel</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
        </nav>
        <div class="mt-5">
            <h1 class="display-4">Experience Luxury Like Never Before</h1>
            <p class="lead">Book your stay with us and enjoy world-class amenities.</p>
            <form class="mt-4" method="get" action="/">
                <div class="mb-3">
                    <label for="search" class="form-label">Search our site</label>
                    <input type="text" class="form-control" id="search" name="q" value="{{ search_query|safe }}">
                </div>
                <button type="submit" class="btn btn-primary">Search</button>
            </form>
            {% if search_query %}
            <p class="mt-3">You searched for: {{ search_query|safe }}</p>
            {% endif %}
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''
    return render_template_string(html_content, search_query=search_query)

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True, host='0.0.0.0', port=5000)