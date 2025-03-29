from flask import Flask, render_template_string, request, redirect, url_for
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('fitness.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS members (id INTEGER PRIMARY KEY, name TEXT, membership_type TEXT, visible INTEGER)''')
    # Insert a default user
    c.execute("INSERT INTO users (username, password) VALUES ('member', 'fitness123')")
    # Insert some members
    members = [
        ('John Doe', 'Premium', 1),
        ('Jane Smith', 'Standard', 1),
        ('Alice Johnson', 'Premium', 1),
        ('Bob Brown', 'Standard', 1),
        ('Admin User', 'Admin Access', 0),
    ]
    c.executemany("INSERT INTO members (name, membership_type, visible) VALUES (?, ?, ?)", members)
    conn.commit()
    conn.close()

init_db()

home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Elite Fitness Center</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Welcome to Elite Fitness Center</h1>
        <p>Your journey to a healthier life starts here.</p>
        <a href="{{ url_for('login') }}" class="btn btn-primary">Member Login</a>
        <a href="{{ url_for('members') }}" class="btn btn-info">Member Directory</a>
    </div>
</body>
</html>
'''

login_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Member Login - Elite Fitness Center</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h2 class="mt-5">Member Login</h2>
        {% if error %}
            <div class="alert alert-danger">{{ error }}</div>
        {% endif %}
        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" name="username" id="username" class="form-control" placeholder="Enter username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" name="password" id="password" class="form-control" placeholder="Enter password" required>
            </div>
            <button type="submit" class="btn btn-success">Login</button>
            <a href="{{ url_for('home') }}" class="btn btn-secondary">Back to Home</a>
        </form>
    </div>
</body>
</html>
'''

members_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Member Directory - Elite Fitness Center</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h2 class="mt-5">Member Directory</h2>
        <form method="POST">
            <div class="form-group">
                <label for="name">Search Members by Name:</label>
                <input type="text" name="name" id="name" class="form-control" placeholder="Enter name">
            </div>
            <button type="submit" class="btn btn-primary">Search</button>
            <a href="{{ url_for('home') }}" class="btn btn-secondary">Back to Home</a>
        </form>
        {% if results %}
            <h3 class="mt-5">Search Results:</h3>
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Membership Type</th>
                    </tr>
                </thead>
                <tbody>
                    {% for member in results %}
                    <tr>
                        <td>{{ member[1] }}</td>
                        <td>{{ member[2] }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        {% endif %}
    </div>
</body>
</html>
'''

congratulations_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #d4edda; }
    </style>
</head>
<body>
    <div class="container">
        <h2 class="mt-5 text-success">Congratulations!</h2>
        <p>You have successfully exploited the SQL Injection vulnerability.</p>
    </div>
</body>
</html>
'''

success_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome Member - Elite Fitness Center</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h2 class="mt-5">Welcome, Elite Member!</h2>
        <p>You have successfully logged in.</p>
    </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('fitness.db')
        c = conn.cursor()

        # Vulnerable query
        query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(username, password)
        try:
            c.execute(query)
            result = c.fetchone()
            if result:
                return redirect(url_for('success'))
            else:
                error = 'Invalid credentials. Please try again.'
        except sqlite3.Error as e:
            error = 'An error occurred.'
        conn.close()

    return render_template_string(login_template, error=error)

@app.route('/success')
def success():
    return render_template_string(success_template)

@app.route('/members', methods=['GET', 'POST'])
def members():
    results = []
    if request.method == 'POST':
        name = request.form['name']

        conn = sqlite3.connect('fitness.db')
        c = conn.cursor()

        # Vulnerable query
        query = "SELECT * FROM members WHERE name LIKE '%{}%' AND visible = 1".format(name)
        try:
            c.execute(query)
            results = c.fetchall()
        except sqlite3.Error as e:
            results = []
        conn.close()

        # Check if 'Admin User' is in results
        if any('Admin User' == member[1] for member in results):
            return render_template_string(congratulations_template)

    return render_template_string(members_template, results=results)
if __name__ == '__main__':
        app.run(debug=True)