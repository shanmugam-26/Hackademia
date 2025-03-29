from flask import Flask, request, render_template_string

app = Flask(__name__)

template = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Elite Fitness Center</title>
    <!-- Include Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">Elite Fitness Center</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"       aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
</nav>
<div class="container mt-5">
    <h1>Welcome to Elite Fitness Center</h1>
    <p>Your journey to a healthier life starts here.</p>
    <h3>Leave Your Feedback</h3>
    <form method="POST">
        <div class="form-group">
            <label for="feedback">Your thoughts:</label>
            <input type="text" class="form-control" id="feedback" name="feedback" placeholder="Enter your feedback">
        </div>
        <button type="submit" class="btn btn-primary">Submit</button>
    </form>
    {% if feedback %}
    <div class="mt-4">
        <h4>Your feedback:</h4>
        <p>{{ feedback }}</p>
    </div>
    {% endif %}
    <div id="congrats" style="display:none; margin-top:20px;">
        <h2>Congratulations!</h2>
        <p>You have successfully exploited the vulnerability.</p>
    </div>
</div>
<!-- Include Bootstrap JS and dependencies -->
<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    feedback = ''
    if request.method == 'POST':
        feedback = request.form.get('feedback', '')
    return render_template_string(template, feedback=feedback)
if __name__ == '__main__':
        app.run(debug=True)