from flask import Flask, request, render_template_string, abort
import os

app = Flask(__name__)

SECRET_FILE = 'congratulations.txt'

# Simulated file system
FILES = {
    'manuals/game1.txt': 'Game 1 Manual Content',
    'manuals/game2.txt': 'Game 2 Manual Content',
    'manuals/game3.txt': 'Game 3 Manual Content',
    'congratulations.txt': 'Congratulations! You have found the secret file and successfully exploited the directory traversal vulnerability!',
}

@app.route('/')
def index():
    return render_template_string('''
<html>
<head>
    <title>GamerZone - The Ultimate Online Gaming Platform</title>
    <style>
        body {
            background-color: #1e1e1e;
            color: #eee;
            font-family: Arial, sans-serif;
        }
        h1 {
            color: #ff4081;
            text-align: center;
            padding-top: 50px;
        }
        .container {
            width: 80%;
            margin: auto;
            text-align: center;
        }
        .game-card {
            display: inline-block;
            background-color: #2e2e2e;
            width: 200px;
            margin: 20px;
            padding: 10px;
            border-radius: 10px;
        }
        .game-card img {
            width: 100%;
            border-radius: 10px;
        }
        .game-card h3 {
            color: #ff4081;
            margin-top: 10px;
        }
        .download-link {
            text-decoration: none;
            color: #ff4081;
        }
    </style>
</head>
<body>
    <h1>Welcome to GamerZone!</h1>
    <div class="container">
        <div class="game-card">
            <img src="https://via.placeholder.com/200x150.png?text=Space+Adventure">
            <h3>Space Adventure</h3>
            <a href="/download?file=game1.txt" class="download-link">Download Manual</a>
        </div>
        <div class="game-card">
            <img src="https://via.placeholder.com/200x150.png?text=Race+Master">
            <h3>Race Master</h3>
            <a href="/download?file=game2.txt" class="download-link">Download Manual</a>
        </div>
        <div class="game-card">
            <img src="https://via.placeholder.com/200x150.png?text=Puzzle+Challenge">
            <h3>Puzzle Challenge</h3>
            <a href="/download?file=game3.txt" class="download-link">Download Manual</a>
        </div>
    </div>
</body>
</html>
''')

@app.route('/download')
def download():
    filename = request.args.get('file', '')
    if filename == '':
        abort(404)
    # Flawed sanitization: Remove instances of '../'
    sanitized_filename = filename.replace('../', '')
    # Construct the file path
    filepath = os.path.normpath(os.path.join('manuals', sanitized_filename))
    # Prevent access to files outside the 'manuals' directory
    if not filepath.startswith('manuals'):
        abort(403)
    # Check if file exists
    if filepath not in FILES:
        abort(404)
    content = FILES[filepath]
    # Serve the file content
    return render_template_string('''
<html>
<head>
    <title>Download</title>
</head>
<body>
    <h1>Download File: {{ filename }}</h1>
    <pre>{{ content }}</pre>
</body>
</html>
''', filename=filename, content=content)

@app.errorhandler(404)
def page_not_found(e):
    return render_template_string('''
<html>
<head>
    <title>404 - File Not Found</title>
</head>
<body>
    <h1>Oops! The file you requested was not found.</h1>
</body>
</html>
'''), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template_string('''
<html>
<head>
    <title>403 - Forbidden</title>
</head>
<body>
    <h1>Access Denied.</h1>
</body>
</html>
'''), 403

if __name__ == '__main__':
    app.run(debug=True)