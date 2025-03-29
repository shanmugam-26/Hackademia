from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'

DATABASE = 'users.db'

# Initialize the database
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    # Insert the admin user with MD5 hashed password 'admin123'
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        password = 'admin123'
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', ('admin', hashed_password))
    conn.commit()
    conn.close()

init_db()

# Global HTML template using Bootstrap
html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>EliteFashion - {{ title }}</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="/">EliteFashion</a>
  <div class="collapse navbar-collapse">
    <ul class="navbar-nav mr-auto">
      {% if 'username' in session %}
      <li class="nav-item">
        <a class="nav-link" href="/logout">Logout ({{ session['username'] }})</a>
      </li>
      {% else %}
      <li class="nav-item">
        <a class="nav-link" href="/login">Login</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="/register">Register</a>
      </li>
      {% endif %}
    </ul>
  </div>
</nav>
<div class="container">
    {{ content | safe }}
</div>
</body>
</html>
'''

base_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>EliteFashion - {{ title }}</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="/">EliteFashion</a>
  <div class="collapse navbar-collapse">
    <ul class="navbar-nav mr-auto">
      {% if 'username' in session %}
      <li class="nav-item">
        <a class="nav-link" href="/logout">Logout ({{ session['username'] }})</a>
      </li>
      {% else %}
      <li class="nav-item">
        <a class="nav-link" href="/login">Login</a>
      </li>
      <li class="nav-item">
        <a class="nav-link" href="/register">Register</a>
      </li>
      {% endif %}
    </ul>
  </div>
</nav>

<div class="container">
    {% block content %}{% endblock %}
</div>

</body>
</html>
'''

@app.route('/')
def home():
    content = """
    <div class="jumbotron">
        <h1 class="display-4">Welcome to EliteFashion</h1>
        <p class="lead">Discover the latest trends in fashion.</p>
        <hr class="my-4">
        {% if 'username' in session %}
        <p>Hello, {{ session['username'] }}!</p>
        {% else %}
        <p>Please <a href="/login">login</a> or <a href="/register">register</a>.</p>
        {% endif %}
    </div>
    """
    return render_template_string(html_template, content=content, title='Home')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.md5(password.encode()).hexdigest()  # Insecure hashing
        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = 'Username already exists.'
    return render_template_string(html_template + '''
    {% block content %}
    <h2>Register</h2>
    {% if error %}
    <div class="alert alert-danger">{{ error }}</div>
    {% endif %}
    <form method="post">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" class="form-control" name="username" required>
      </div>
      <div class="form-group">
         <label for="password">Password</label>
         <input type="password" class="form-control" name="password" required>
      </div>
      <button type="submit" class="btn btn-primary">Register</button>
    </form>
    {% endblock %}
    ''', title='Register', error=error)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.md5(password.encode()).hexdigest()  # Insecure hashing
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        user = cursor.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            error = 'Invalid username or password.'
    return render_template_string(html_template + '''
    {% block content %}
    <h2>Login</h2>
    {% if error %}
    <div class="alert alert-danger">{{ error }}</div>
    {% endif %}
    <form method="post">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" class="form-control" name="username" required>
      </div>
      <div class="form-group">
         <label for="password">Password</label>
         <input type="password" class="form-control" name="password" required>
      </div>
      <button type="submit" class="btn btn-primary">Login</button>
    </form>
    {% endblock %}
    ''', title='Login', error=error)

# Logout
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

# Admin page
@app.route('/admin')
def admin():
    if 'username' in session and session['username'] == 'admin':
        return render_template_string(html_template + '''
        {% block content %}
        <h2>Congratulations!</h2>
        <p>You have successfully exploited the vulnerability.</p>
        {% endblock %}
        ''', title='Admin')
    else:
        return redirect(url_for('home'))
if __name__ == '__main__':
          app.run(debug=True, host='0.0.0.0', port=5000)