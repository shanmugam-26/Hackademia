from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS clients (id INTEGER PRIMARY KEY, name TEXT, case_details TEXT)')
    c.execute("INSERT INTO clients (name, case_details) VALUES ('John Doe', 'Confidential Case A'), ('Jane Smith', 'Confidential Case B')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Anderson & Parker Law Firm</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #f8f9fa; }
        .navbar { margin-bottom: 30px; }
        .footer { margin-top: 30px; padding: 20px 0; background-color: #343a40; color: #fff; text-align: center; }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <a class="navbar-brand" href="#">Anderson & Parker</a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExample07"
    aria-controls="navbarsExample07" aria-expanded="false" aria-label="Toggle navigation">
    <span class="navbar-toggler-icon"></span>
  </button>
</nav>

<div class="container">
    <div class="jumbotron">
        <h1 class="display-4">Welcome to Anderson & Parker Law Firm</h1>
        <p class="lead">Excellence in Legal Service Since 1990</p>
        <hr class="my-4">
        <p>Our firm specializes in corporate law, intellectual property, and litigation.</p>
    </div>
    <h2>Client Portal</h2>
    <p>Please search for your case details using your name:</p>
    <form action="/search" method="post" class="form-inline">
        <div class="form-group mb-2">
            <label for="name" class="sr-only">Client Name</label>
            <input type="text" class="form-control" id="name" name="name" placeholder="Enter your name">
        </div>
        <button type="submit" class="btn btn-primary mb-2 ml-2">Search</button>
    </form>
</div>

<footer class="footer">
    <div class="container">
        &copy; 2023 Anderson & Parker Law Firm. All rights reserved.
    </div>
</footer>
</body>
</html>
    ''')

@app.route('/search', methods=['POST'])
def search():
    name = request.form['name']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Vulnerable SQL query
    query = "SELECT * FROM clients WHERE name = '%s'" % name
    try:
        c.execute(query)
        results = c.fetchall()
    except Exception as e:
        conn.close()
        return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Error - Anderson & Parker Law Firm</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h1 class="mt-5">An error has occurred</h1>
    <p class="lead">Please contact support.</p>
    <a href="/" class="btn btn-secondary">Back to Home</a>
</div>
</body>
</html>
        ''')

    conn.close()

    if not results:
        message = "No records found for the provided name."
    else:
        message = f"Found {len(results)} record(s):"
        for row in results:
            message += f"<br><strong>Client ID:</strong> {row[0]}"
            message += f"<br><strong>Name:</strong> {row[1]}"
            message += f"<br><strong>Case Details:</strong> {row[2]}"
            message += "<hr>"
        # Check if the user exploited the vulnerability
        if len(results) > 2:
            message += "<h3>Congratulations!</h3><p>You have successfully exploited the vulnerability.</p>"
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Search Results - Anderson & Parker Law Firm</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h1 class="mt-5">Search Results</h1>
    <p class="lead">{{ message|safe }}</p>
    <a href="/" class="btn btn-secondary">Back to Home</a>
</div>
</body>
</html>
    ''', message=message)
if __name__ == '__main__':
        init_db()
        app.run(debug=True, host='0.0.0.0', port=5000)