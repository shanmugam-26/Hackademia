from flask import Flask, render_template_string, request, send_from_directory
import os

app = Flask(__name__)

# Simulate a secret file on the server (e.g., containing passwords or other sensitive info)
secret_file_path = 'secret_config.txt'

# Create a secret file with sensitive data
with open(secret_file_path, 'w') as f:
    f.write('Congratulations! You have found the secret data!\n')
    f.write('Here is your flag: FLAG{Sensitive_Data_Exposure_Challenge_Completed}\n')

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Ultimate Online Gaming Platform</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; }
        .header { background-color: #1f1f1f; padding: 20px; text-align: center; }
        .header h1 { margin: 0; }
        .nav { display: flex; justify-content: center; background-color: #272727; }
        .nav a { padding: 14px 20px; color: #e0e0e0; text-decoration: none; }
        .nav a:hover { background-color: #575757; }
        .content { padding: 20px; }
        .game-list { display: flex; flex-wrap: wrap; justify-content: center; }
        .game { background-color: #1f1f1f; margin: 10px; padding: 20px; width: 200px; text-align: center; }
        .game img { width: 100%; }
        .footer { background-color: #1f1f1f; padding: 10px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Ultimate Online Gaming Platform</h1>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/games">Games</a>
        <a href="/support">Support</a>
    </div>
    <div class="content">
        <h2>Welcome, gamer!</h2>
        <p>Enjoy the best games online with friends and players from all over the world.</p>
    </div>
    <div class="footer">
        <p>&copy; 2023 Ultimate Gaming Inc.</p>
    </div>
</body>
</html>
''')

@app.route('/games')
def games():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Games - Ultimate Online Gaming Platform</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; }
        .header { background-color: #1f1f1f; padding: 20px; text-align: center; }
        .header h1 { margin: 0; }
        .nav { display: flex; justify-content: center; background-color: #272727; }
        .nav a { padding: 14px 20px; color: #e0e0e0; text-decoration: none; }
        .nav a:hover { background-color: #575757; }
        .content { padding: 20px; }
        .game-list { display: flex; flex-wrap: wrap; justify-content: center; }
        .game { background-color: #1f1f1f; margin: 10px; padding: 20px; width: 200px; text-align: center; }
        .game img { width: 100%; }
        .game p { margin-top: 10px; }
        .footer { background-color: #1f1f1f; padding: 10px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Ultimate Online Gaming Platform</h1>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/games">Games</a>
        <a href="/support">Support</a>
    </div>
    <div class="content">
        <h2>Our Games</h2>
        <div class="game-list">
            <div class="game">
                <img src="/static/game1.jpg" alt="Game 1">
                <p>Adventure Quest</p>
            </div>
            <div class="game">
                <img src="/static/game2.jpg" alt="Game 2">
                <p>Space Invaders</p>
            </div>
            <div class="game">
                <img src="/static/game3.jpg" alt="Game 3">
                <p>Fantasy Realm</p>
            </div>
        </div>
    </div>
    <div class="footer">
        <p>&copy; 2023 Ultimate Gaming Inc.</p>
    </div>
</body>
</html>
''')

@app.route('/support')
def support():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Support - Ultimate Online Gaming Platform</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; }
        .header { background-color: #1f1f1f; padding: 20px; text-align: center; }
        .header h1 { margin: 0; }
        .nav { display: flex; justify-content: center; background-color: #272727; }
        .nav a { padding: 14px 20px; color: #e0e0e0; text-decoration: none; }
        .nav a:hover { background-color: #575757; }
        .content { padding: 20px; }
        .footer { background-color: #1f1f1f; padding: 10px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Ultimate Online Gaming Platform</h1>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/games">Games</a>
        <a href="/support">Support</a>
    </div>
    <div class="content">
        <h2>Support</h2>
        <p>If you encounter any issues, please contact our support team at <a href="mailto:support@ultimate-gaming.com">support@ultimate-gaming.com</a>.</p>
    </div>
    <div class="footer">
        <p>&copy; 2023 Ultimate Gaming Inc.</p>
    </div>
</body>
</html>
''')

@app.route('/download')
def download():
    filename = request.args.get('file')
    if filename:
        try:
            # Vulnerable to directory traversal attack
            return send_from_directory('.', filename)
        except FileNotFoundError:
            return "File not found", 404
    else:
        return "No file specified", 400

if __name__ == '__main__':
    # Start the Flask app
    app.run(host='0.0.0.0', port=5000)