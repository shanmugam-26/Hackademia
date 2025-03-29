from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Realty - Real Estate Agency</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h1 class="mt-5">Welcome to Global Realty</h1>
    <p>Find your global dream home today. Please <a href="{{ url_for('login') }}">Login</a> to access exclusive listings.</p>
</div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Agent Login - Global Realty</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Agent Portal Login</h2>
    {% if error %}
    <div class="alert alert-danger" role="alert">
        {{ error }}
    </div>
    {% endif %}
    <form method="post">
        <div class="form-group">
            <label for="username">Agent Username</label>
            <input type="text" class="form-control" id="username" name="username" placeholder="Enter Agent Username">
        </div>
        <div class="form-group">
            <label for="password">Access Key</label>
            <input type="password" class="form-control" id="password" name="password" placeholder="Access Key">
        </div>
        <button type="submit" class="btn btn-primary">Access Portal</button>
    </form>
</div>
</body>
</html>
'''

welcome_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Exclusive Listings</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Exclusive Listings</h2>
    <p>Congratulations! You have gained access to the exclusive listings.</p>
    <p>Here are our top properties:</p>
    <ul>
        <li>Luxury Villa in Beverly Hills</li>
        <li>Penthouse Apartment in Manhattan</li>
        <li>Beachfront Property in Miami</li>
    </ul>
</div>
</body>
</html>
'''

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)''')
    c.execute("DELETE FROM users")  # Clear table if re-running
    c.execute("INSERT INTO users VALUES ('agent1', 'password1')")
    c.execute("INSERT INTO users VALUES ('agent2', 'password2')")
    c.execute("INSERT INTO users VALUES ('agent3', 'password3')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if authenticate(username, password):
            return render_template_string(welcome_template)
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template_string(login_template, error=error)

def authenticate(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Vulnerable query (Authentication Bypass opportunity)
    query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(username, password)
    c.execute(query)
    result = c.fetchone()
    conn.close()
    if result:
        return True
    else:
        return False
if __name__ == '__main__':
        app.run(debug=True)