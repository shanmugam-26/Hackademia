from flask import Flask, render_template_string, request, redirect, url_for, jsonify
import base64
import hashlib
import threading

app = Flask(__name__)

users = {
    'alice': 'password123',
    'bob': 'qwerty',
    'charlie': 'letmein'
}

messages = {
    'alice': 'Your appointment is scheduled on Oct 15th, 10:00 AM.',
    'bob': 'Your lab results are normal.',
    'charlie': 'Please update your insurance information.'
}

def generate_token(username):
    token_str = f"{username}:{users[username]}"
    token_bytes = token_str.encode('utf-8')
    return base64.b64encode(token_bytes).decode('utf-8')

# Home page
@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>ABC Healthcare Provider</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f0f8ff;}
            .container {width: 60%; margin: auto;}
            h1 {text-align: center; color: #2e8b57;}
            form {border: 3px solid #f1f1f1; padding: 10px;}
            input[type=text], input[type=password] {
                width: 100%;
                padding: 12px 20px;
                margin: 8px 0;
                border: 1px solid #ccc;
                box-sizing: border-box;
            }
            input[type=submit] {
                background-color: #4CAF50;
                color: white;
                padding: 14px 20px;
                margin: 8px 0;
                border: none;
                cursor: pointer;
                width: 100%;
            }
            input[type=submit]:hover {
                opacity: 0.8;
            }
        </style>
        <script>
            function checkTLS() {
                if (location.protocol !== 'https:') {
                    document.getElementById('tls-warning').style.display = 'block';
                }
            }
        </script>
    </head>
    <body onload="checkTLS()">
        <div class="container">
            <h1>Welcome to ABC Healthcare Provider</h1>
            <p>Providing quality healthcare services since 1990.</p>
            <div id="tls-warning" style="display:none; color:red;">
                Warning: Your connection is not secure.
            </div>
            <form action="/login" method="POST">
                <div class="container">
                    <label for="uname"><b>Username</b></label>
                    <input type="text" placeholder="Enter Username" name="username" required>
                    <label for="psw"><b>Password</b></label>
                    <input type="password" placeholder="Enter Password" name="password" required>
                    <input type="submit" value="Login">
                </div>
            </form>
        </div>
    </body>
    </html>
    ''')

# Login route (vulnerable to insecure communication)
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username in users and users[username] == password:
        token = generate_token(username)
        # Redirect to profile with token in URL (insecure)
        return redirect(url_for('profile', username=username, token=token))
    else:
        return redirect(url_for('home'))

# Profile page
@app.route('/profile/<username>')
def profile(username):
    token = request.args.get('token', '')
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{ username }}'s Profile - ABC Healthcare</title>
        <script>
            function loadMessage() {
                fetch('/message?username={{ username }}&token={{ token }}')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('message').innerText = data.message;
                });
            }
        </script>
    </head>
    <body onload="loadMessage()">
        <h1>Hello, {{ username }}!</h1>
        <p>Welcome to your personal dashboard.</p>
        <h2>Your Message:</h2>
        <p id="message">Loading...</p>
    </body>
    </html>
    ''', username=username, token=token)

# Message API (vulnerable to token interception)
@app.route('/message')
def get_message():
    username = request.args.get('username', '')
    token = request.args.get('token', '')
    if username in users:
        expected_token = generate_token(username)
        if token == expected_token:
            return jsonify({'message': messages.get(username, '')})
    return jsonify({'message': 'Invalid token.'})

# Hidden congratulations route
@app.route('/congratulations')
def congratulations():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Congratulations!</title>
    </head>
    <body>
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the vulnerability.</p>
    </body>
    </html>
    ''')

def run_server():
    app.run(debug=False, host='0.0.0.0', port=80)

if __name__ == '__main__':
    threading.Thread(target=run_server).start()