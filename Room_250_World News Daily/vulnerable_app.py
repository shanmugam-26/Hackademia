from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3

app = Flask(__name__)

# Initialize the database
def init_db():
    conn = sqlite3.connect('news.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS articles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        content TEXT
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
    )
    ''')
    # Insert sample data
    cursor.execute("INSERT INTO articles (title, content) VALUES ('Breaking News', 'This is the latest breaking news content.')")
    cursor.execute("INSERT INTO articles (title, content) VALUES ('Technology Update', 'New tech products are released.')")
    cursor.execute("INSERT INTO articles (title, content) VALUES ('Economy Insights', 'Economic growth has been steady.')")
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'supersecretpassword')")
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return render_template_string(home_template)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = sqlite3.connect('news.db')
    cursor = conn.cursor()
    # Vulnerable to SQL Injection
    sql_query = "SELECT title, content FROM articles WHERE title LIKE '%{}%'".format(query)
    try:
        cursor.execute(sql_query)
        results = cursor.fetchall()
    except Exception as e:
        results = []
    conn.close()

    # Check for exploitation
    if 'admin' in query.lower():
        return redirect(url_for('congrats'))

    return render_template_string(search_template, query=query, results=results)

@app.route('/congrats')
def congrats():
    return render_template_string(congrats_template)

home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>World News Daily</title>
    <!-- Include Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <a class="navbar-brand" href="#">World News Daily</a>
    </nav>
    <div class="container mt-4">
        <h1>Welcome to World News Daily</h1>
        <p>Your source for the latest news around the globe.</p>
        <form action="/search" method="get" class="mt-4">
            <div class="input-group mb-3">
                <input type="text" class="form-control" placeholder="Search articles..." name="q">
                <button class="btn btn-primary">Search</button>
            </div>
        </form>
        <h2>Featured Articles</h2>
        <div class="card mb-3">
            <div class="card-body">
                <h5 class="card-title">Breaking News</h5>
                <p class="card-text">This is the latest breaking news content.</p>
            </div>
        </div>
    </div>
</body>
</html>
'''

search_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Search Results - World News Daily</title>
    <!-- Include Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <a class="navbar-brand" href="#">World News Daily</a>
    </nav>
    <div class="container mt-4">
        <h1>Search Results for "{{ query }}"</h1>
        {% if results %}
            {% for title, content in results %}
                <div class="card mb-3">
                    <div class="card-body">
                        <h5 class="card-title">{{ title }}</h5>
                        <p class="card-text">{{ content }}</p>
                    </div>
                </div>
            {% endfor %}
        {% else %}
            <p>No articles found matching your query.</p>
        {% endif %}
        <a href="/" class="btn btn-secondary mt-3">Back to Home</a>
    </div>
</body>
</html>
'''

congrats_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <!-- Include Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container text-center mt-5">
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the SQL Injection vulnerability.</p>
    </div>
</body>
</html>
'''

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)