from flask import Flask, render_template_string, request, send_file
import os

app = Flask(__name__)

# Sample in-memory database of games
games = [
    {'title': 'Space Adventure', 'description': 'Explore the universe and uncover its secrets.'},
    {'title': 'Mystic Quest', 'description': 'Embark on a journey through enchanted lands.'},
    {'title': 'Cyber Race', 'description': 'Compete in high-speed races across futuristic cities.'},
]

# Template with modern CSS framework (e.g., Bulma)
base_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>EpicGame Hub</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.3/css/bulma.min.css">
</head>
<body>
<section class="section">
    <div class="container">
        <h1 class="title">Welcome to EpicGame Hub</h1>
        <p class="subtitle">Your gateway to the most exciting games online.</p>
        <div class="columns is-multiline">
            {% for game in games %}
            <div class="column is-one-third">
                <div class="card">
                    <div class="card-content">
                        <p class="title">{{ game.title }}</p>
                        <p class="subtitle">{{ game.description }}</p>
                    </div>
                    <footer class="card-footer">
                        <a href="/play?game={{ game.title }}" class="card-footer-item">Play Now</a>
                        <a href="/download?file={{ game.title }}.pdf" class="card-footer-item">Download Guide</a>
                    </footer>
                </div>
            </div>
            {% endfor %}
        </div>
    </div>
</section>
</body>
</html>
"""

# Route for the home page
@app.route('/')
def home():
    return render_template_string(base_template, games=games)

# Vulnerable route (Directory Traversal)
@app.route('/download')
def download():
    file = request.args.get('file', '')
    file_path = os.path.join('guides', file)
    if os.path.isfile(file_path):
        return send_file(file_path)
    else:
        return "File not found.", 404

# Play game route
@app.route('/play')
def play():
    game = request.args.get('game', 'Game')
    return render_template_string("""
    <html>
    <head>
        <title>Playing {{ game }}</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.3/css/bulma.min.css">
    </head>
    <body>
    <section class="section">
        <div class="container">
            <h1 class="title">Now Playing: {{ game }}</h1>
            <p class="subtitle">Enjoy your game!</p>
            <a href="/" class="button is-primary">Back to Home</a>
        </div>
    </section>
    </body>
    </html>
    """, game=game)

# Congratulations route
@app.route('/congrats')
def congrats():
    return render_template_string("""
    <html>
    <head>
        <title>Congratulations!</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.3/css/bulma.min.css">
    </head>
    <body>
    <section class="section">
        <div class="container has-text-centered">
            <h1 class="title">Congratulations!</h1>
            <p class="subtitle">You have successfully exploited the vulnerability.</p>
        </div>
    </section>
    </body>
    </html>
    """)
if __name__ == '__main__':
        app.run(debug=True, port=5000)