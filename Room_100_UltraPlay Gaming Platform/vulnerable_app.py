from flask import Flask, render_template_string, request, redirect, make_response
import pickle
import base64
import os

app = Flask(__name__)

app.secret_key = os.urandom(24)

# User class for demonstration purposes
class User:
    def __init__(self, username, is_admin=False):
        self.username = username
        self.is_admin = is_admin

@app.route('/', methods=['GET', 'POST'])
def index():
    # Default user
    user = User('Guest')

    # Check for user data in cookies
    user_cookie = request.cookies.get('user_data')
    if user_cookie:
        try:
            # Vulnerable deserialization
            user = pickle.loads(base64.b64decode(user_cookie))
        except Exception as e:
            pass  # Ignore errors in deserialization

    if request.method == 'POST':
        username = request.form.get('username')
        user = User(username)
        # Serialize user object
        user_data = base64.b64encode(pickle.dumps(user)).decode()
        resp = make_response(redirect('/'))
        resp.set_cookie('user_data', user_data)
        return resp

    if user.is_admin:
        message = "🎉 Congratulations! You've successfully exploited the vulnerability and are now an admin!"
    else:
        message = f"Welcome, {user.username}! Ready to play the most exciting games online?"

    # HTML template using Bootstrap for modern design
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>UltraPlay Gaming Platform</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            body {
                background: linear-gradient(to right, #000428, #004e92);
                color: #ffffff;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            .container {
                margin-top: 100px;
            }
            .card {
                background-color: rgba(0, 0, 0, 0.7);
                border: none;
            }
            .btn-custom {
                background-color: #1f4037;
                border-color: #1f4037;
            }
            .btn-custom:hover {
                background-color: #99f2c8;
                border-color: #99f2c8;
                color: #000;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card mx-auto" style="max-width: 500px;">
                <div class="card-body text-center">
                    <h1 class="card-title">UltraPlay Gaming Platform</h1>
                    <p class="card-text">{{ message }}</p>
                    {% if not user.is_admin %}
                    <form method="post">
                        <div class="form-group">
                            <input type="text" class="form-control" name="username" placeholder="Enter new username" required>
                        </div>
                        <button type="submit" class="btn btn-custom btn-block">Update Username</button>
                    </form>
                    {% else %}
                    <a href="/" class="btn btn-custom btn-block">Logout</a>
                    {% endif %}
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(template, user=user)
if __name__ == '__main__':
        app.run(debug=True, port=5000)