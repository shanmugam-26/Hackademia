from flask import Flask, render_template_string, request, jsonify
import sqlite3

app = Flask(__name__)

# Secret API key (This should not be exposed)
SECRET_API_KEY = "SuperSecretAPIKey123456789"

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>TranspoFast - Your Reliable Transportation Service</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="/">TranspoFast</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"
                aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
    </nav>
    <div class="container">
        <h1>Welcome to TranspoFast!</h1>
        <p>Your trusted partner for quick and reliable transportation services.</p>
        <!-- TODO: Remove API key before deploying to production -->
        <!-- API Key: {{ api_key }} -->
    </div>
    <script src="https://code.jquery.com/jquery-3.7.1.slim.min.js"
            integrity="sha384-Jl+QWgsCSwSfz84anvhVGOAVIc4pdnj6SM1wiZf8utXaF0nErkNo1yVZNyD3lsyg"
            crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"
            integrity="sha384-ENjdO4Dr2bkBIFxQpeo6eZ9GGLZbkprk2eDZ1UGkPxhZUsoe2OOv4+0C6Legm0Xj"
            crossorigin="anonymous"></script>
    </body>
    </html>
    ''', api_key=SECRET_API_KEY)

@app.route('/get_user_data', methods=['POST'])
def get_user_data():
    user_id = request.form.get('user_id')
    # Simulate database lookup
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id=?", (user_id,))
        user = c.fetchone()
        if user:
            data = {
                'id': user[0],
                'name': user[1],
                'email': user[2],
            }
            return jsonify(data)
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        return str(e), 500

@app.route('/validate_api_key', methods=['POST'])
def validate_api_key():
    api_key = request.form.get('api_key')
    if api_key == SECRET_API_KEY:
        return "Congratulations! You have found the secret API key and exploited the vulnerability!"
    else:
        return "Invalid API key.", 403
if __name__ == '__main__':
            app.run(debug=True, host='0.0.0.0', port=5000)