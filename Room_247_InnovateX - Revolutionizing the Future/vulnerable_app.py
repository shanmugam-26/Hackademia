from flask import Flask, render_template_string, request
import sqlite3

app = Flask(__name__)

# Initialize the database
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT,
                 password TEXT)''')
    # Insert sample users
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'password123')")
    c.execute("INSERT INTO users (username, password) VALUES ('user', 'mypassword')")
    conn.commit()
    conn.close()

init_db()

# HTML template with modern CSS framework
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>InnovateX - Revolutionizing the Future</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container py-5">
    <h1 class="text-center mb-4">Welcome to InnovateX</h1>
    <p class="text-center">Join us in shaping the future of technology.</p>
    <div class="row justify-content-center">
        <div class="col-md-6">
            <form method="POST" action="/search">
                <div class="mb-3">
                    <label for="keyword" class="form-label">Search Our Talent Pool</label>
                    <input type="text" class="form-control" id="keyword" name="keyword" placeholder="Enter keyword">
                </div>
                <button type="submit" class="btn btn-primary w-100">Search</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>
"""

# Congratulations template
congrats_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container py-5">
    <h1 class="text-center mb-4">Congratulations!</h1>
    <p class="text-center">You have successfully exploited the SQL Injection vulnerability.</p>
</div>
</body>
</html>
"""

# Search Results template
results_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Search Results</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container py-5">
    <h1 class="mb-4">Search Results</h1>
    <ul class="list-group">
    {% for user in users %}
        <li class="list-group-item">{{ user[1] }}</li>
    {% endfor %}
    </ul>
    <a href="/" class="btn btn-secondary mt-4">Back to Home</a>
</div>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return render_template_string(html_template)

@app.route('/search', methods=['POST'])
def search():
    keyword = request.form['keyword']

    # Vulnerable SQL query
    query = "SELECT * FROM users WHERE username LIKE '%{}%'".format(keyword)

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        c.execute(query)
        users = c.fetchall()
        conn.close()
        if users:
            # Check for exploitation
            if len(users) > 2:  # More users than expected indicates possible SQL Injection
                return render_template_string(congrats_template)
            else:
                return render_template_string(results_template, users=users)
        else:
            return "<h1>No Results Found</h1>", 404
    except Exception as e:
        conn.close()
        return "<h1>Error</h1><p>{}</p>".format(e), 500
if __name__ == '__main__':
        app.run(debug=True)