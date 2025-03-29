from flask import Flask, render_template_string, request, redirect, url_for, session
from flask_session import Session
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Configure server-side session
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Simulated user database
users_by_username = {
    'alice': {'id': 1, 'username': 'alice', 'password': 'alicepass', 'name': 'Alice Smith', 'posts': ['Hello world!', 'Lovely day today.']},
    'bob': {'id': 2, 'username': 'bob', 'password': 'bobpass', 'name': 'Bob Johnson', 'posts': ['Excited for the game tonight!', 'Happy Monday everyone!']},
}

users_by_id = {
    1: users_by_username['alice'],
    2: users_by_username['bob'],
    0: {'id': 0, 'username': 'admin', 'password': 'adminpass', 'name': 'Admin', 'posts': ['Top secret data', 'System configurations'], 'is_admin': True},
}

# CSS Framework - Bootstrap CDN
bootstrap_cdn = '''
<!doctype html>
<html lang="en">
  <head>
    <title>MyFace - Social Media Platform</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
  </head>
  <body>
    <!-- Navigation bar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
      <a class="navbar-brand" href="#">MyFace</a>
      <div class="collapse navbar-collapse">
        <ul class="navbar-nav mr-auto">
          {% if session.get('user_id') %}
          <li class="nav-item active">
            <a class="nav-link" href="{{ url_for('profile', id=session['user_id']) }}">Home</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
          </li>
          {% else %}
          <li class="nav-item active">
            <a class="nav-link" href="{{ url_for('index') }}">Login</a>
          </li>
          {% endif %}
        </ul>
      </div>
    </nav>
    <!-- Content -->
    <div class="container mt-4">
'''

# Index page - Login page
@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_by_username.get(username)
        if user and password == user['password']:
            session['user_id'] = user['id']
            return redirect(url_for('profile', id=user['id']))
        else:
            error = 'Invalid credentials'
    return render_template_string(bootstrap_cdn + '''
        <h2>Welcome to MyFace</h2>
        <p>Connect with friends and the world around you.</p>
        <div class="row">
          <div class="col-md-6">
            <h3>Login</h3>
            <form method="post">
                <div class="form-group">
                    <input type="text" name="username" class="form-control" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" class="form-control" placeholder="Password" required>
                </div>
                {% if error %}
                <p style="color:red;">{{ error }}</p>
                {% endif %}
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
          </div>
        </div>
    </div>
  </body>
</html>
    ''', error=error)

# Profile page - Vulnerable to IDOR
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    # Fetch user id from query parameter without checking if it matches the logged-in user's id (IDOR vulnerability)
    user_id = request.args.get('id')
    try:
        user_id = int(user_id)
        user = users_by_id.get(user_id)
        if user:
            if user_id == 0:
                # Show the congratulations message
                return render_template_string(bootstrap_cdn + '''
                    <h2>Congratulations!</h2>
                    <p>You have found the hidden admin profile page!</p>
                    <h4>Admin's Posts:</h4>
                    <ul class="list-group">
                        {% for post in user.posts %}
                        <li class="list-group-item">{{ post }}</li>
                        {% endfor %}
                    </ul>
                </div>
              </body>
            </html>
                ''', user=user)
            else:
                return render_template_string(bootstrap_cdn + '''
                    <h2>{{ user.name }}'s Profile</h2>
                    <h4>Posts:</h4>
                    <ul class="list-group">
                        {% for post in user.posts %}
                        <li class="list-group-item">{{ post }}</li>
                        {% endfor %}
                    </ul>
                </div>
              </body>
            </html>
                ''', user=user)
        else:
            return "User not found", 404
    except (ValueError, TypeError):
        return "Invalid user id", 400

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))
if __name__ == '__main__':
      app.run(debug=True, port=5000)
# Run the app)