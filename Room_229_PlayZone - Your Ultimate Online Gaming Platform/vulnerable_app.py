from flask import Flask, render_template_string, request

app = Flask(__name__)

template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PlayZone - Your Ultimate Online Gaming Platform</title>
    <!-- Bootstrap CSS via CDN -->
    <link rel="stylesheet"
          href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body {
            background-image: url('https://via.placeholder.com/1920x1080');
            background-size: cover;
            background-attachment: fixed;
        }
        .content {
            background: rgba(255,255,255,0.9);
            padding: 20px;
            margin-top: 50px;
            border-radius: 10px;
        }
        .game-list img {
            height: 200px;
            width: auto;
            margin-bottom: 15px;
        }
    </style>
</head>
<body>
    <div class="container content">
        <h1 class="mt-5 text-center">Welcome to PlayZone</h1>
        <p class="lead text-center">Join the ultimate gaming experience!</p>

        <div class="row mt-5">
            <div class="col-md-4">
                <h3>Featured Games</h3>
                <div class="game-list">
                    <img src="https://via.placeholder.com/350x200" class="img-fluid" alt="Game 1">
                    <h5>Space Adventure</h5>
                    <p>Explore the galaxy and uncover its secrets.</p>
                    <img src="https://via.placeholder.com/350x200" class="img-fluid" alt="Game 2">
                    <h5>Dragon Realm</h5>
                    <p>Conquer kingdoms and tame dragons.</p>
                    <img src="https://via.placeholder.com/350x200" class="img-fluid" alt="Game 3">
                    <h5>Speed Racer</h5>
                    <p>Race against the best and become a legend.</p>
                </div>
            </div>
            <div class="col-md-8">
                <h3>Latest News</h3>
                <p>Stay tuned for upcoming tournaments and events!</p>
                <img src="https://via.placeholder.com/750x400" class="img-fluid" alt="News Image">
            </div>
        </div>

        <form method="post" class="mt-5">
            <div class="form-group">
                <label for="message">Share your thoughts about our platform!</label>
                <input type="text" class="form-control" id="message" name="message"
                       placeholder="Enter your message">
            </div>
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>

        {% if message %}
        <div class="alert alert-info mt-3">
            <strong>Latest message:</strong> {{ message|safe }}
        </div>
        {% endif %}

    </div>
    <!-- Bootstrap JS and dependencies via CDN -->
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script
        src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
    <script
        src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>

    <!-- Hidden function for congratulating the user -->
    <script>
    function showCongratulations() {
        alert('Congratulations! You have exploited the vulnerability.');
    }
    </script>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        message = request.form.get('message', '')
    else:
        message = ''
    return render_template_string(template, message=message)
if __name__ == '__main__':
        app.run(debug=True)