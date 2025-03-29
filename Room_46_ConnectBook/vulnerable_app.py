from flask import Flask, render_template_string, request, redirect, url_for, session
import random
import string

app = Flask(__name__)
app.secret_key = ''.join(random.choice(string.ascii_letters) for i in range(16))

bootstrap_cdn = '''
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
'''

secret_message = "Congratulations! You have successfully exploited the SSTI vulnerability!"

users = {'admin': 'password123'}  # Dummy user database
posts = [
    {'author': 'Alice', 'content': 'Just had a great meeting!'},
    {'author': 'Bob', 'content': 'Looking forward to the weekend.'},
    {'author': 'Charlie', 'content': 'Just published a new article on cybersecurity.'}
]

@app.route('/')
def index():
    username = session.get('username')
    return render_template_string('''
    <!doctype html>
    <html lang="en">
    <head>
        <title>ConnectBook</title>
        {{ bootstrap_cdn | safe }}
    </head>
    <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="/">ConnectBook</a>
      <div class="collapse navbar-collapse">
        <ul class="navbar-nav ml-auto">
            {% if username %}
            <li class="nav-item">
                <a class="nav-link" href="/update_status">Update Status</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="/logout">Logout</a>
            </li>
            {% else %}
            <li class="nav-item">
                <a class="nav-link" href="/login">Login</a>
            </li>
            {% endif %}
        </ul>
      </div>
    </nav>
    <div class="container mt-4">
        <h1>Welcome to ConnectBook</h1>
        <p>Connect with professionals around the globe.</p>
        {% if username %}
        <h2>Recent Posts</h2>
        {% for post in posts %}
            <div class="card mb-3">
              <div class="card-body">
                <h5 class="card-title">{{ post.author }}</h5>
                <p class="card-text">{{ post.content }}</p>
              </div>
            </div>
        {% endfor %}
        {% else %}
        <p>Please <a href="/login">login</a> to see recent posts.</p>
        {% endif %}
    </div>
    </body>
    </html>
    ''', bootstrap_cdn=bootstrap_cdn, username=username, posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template_string('''
    <!doctype html>
    <html lang="en">
    <head>
        <title>Login - ConnectBook</title>
        {{ bootstrap_cdn | safe }}
    </head>
    <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="/">ConnectBook</a>
    </nav>
    <div class="container mt-4">
        <h1>Login</h1>
        {% if error %}
        <p class="text-danger">{{ error }}</p>
        {% endif %}
        <form method="POST">
          <div class="form-group">
            <input type="text" class="form-control" name="username" placeholder="Username">
          </div>
          <div class="form-group mt-2">
            <input type="password" class="form-control" name="password" placeholder="Password">
          </div>
          <button type="submit" class="btn btn-primary mt-2">Login</button>
        </form>
    </div>
    </body>
    </html>
    ''', bootstrap_cdn=bootstrap_cdn, error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/update_status', methods=['GET', 'POST'])
def update_status():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))
    global posts
    if request.method == 'POST':
        status = request.form.get('status')
        posts.insert(0, {'author': username, 'content': status})
        # Vulnerable point - rendering the 'status' directly
        return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <title>Status Updated - ConnectBook</title>
            {{ bootstrap_cdn | safe }}
        </head>
        <body>
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
          <a class="navbar-brand" href="/">ConnectBook</a>
          <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link" href="/update_status">Update Status</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/logout">Logout</a>
                </li>
            </ul>
          </div>
        </nav>
        <div class="container mt-4">
            <h1>Your Status</h1>
            <p>{{ status }}</p>
            <a href="/" class="btn btn-primary mt-2">Back to Home</a>
        </div>
        </body>
        </html>
        ''', bootstrap_cdn=bootstrap_cdn, status=status, secret_message=secret_message)
    return render_template_string('''
    <!doctype html>
    <html lang="en">
    <head>
        <title>Update Status - ConnectBook</title>
        {{ bootstrap_cdn | safe }}
    </head>
    <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="/">ConnectBook</a>
      <div class="collapse navbar-collapse">
        <ul class="navbar-nav ml-auto">
            <li class="nav-item">
                <a class="nav-link" href="/update_status">Update Status</a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="/logout">Logout</a>
            </li>
        </ul>
      </div>
    </nav>
    <div class="container mt-4">
        <h1>Update your status</h1>
        <form method="POST">
          <div class="form-group">
            <textarea class="form-control" name="status" rows="3" placeholder="What's on your mind?" required></textarea>
          </div>
          <button type="submit" class="btn btn-primary mt-2">Post</button>
        </form>
    </div>
    </body>
    </html>
    ''', bootstrap_cdn=bootstrap_cdn)
)