from flask import Flask, request, render_template_string, g
import os
import sqlite3

app = Flask(__name__)
DATABASE = 'database.db'

def init_db():
    if not os.path.exists(DATABASE):
        db = sqlite3.connect(DATABASE)
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE policies(
                id INTEGER PRIMARY KEY,
                name TEXT,
                policy_number TEXT,
                sensitive_info TEXT
            )
        ''')
        policies = [
            ('Alice Smith', 'PN1001', 'Alice\'s SSN: 123-45-6789'),
            ('Bob Johnson', 'PN1002', 'Bob\'s SSN: 987-65-4321'),
            ('Charlie Lee', 'PN1003', 'Charlie\'s SSN: 555-55-5555'),
        ]
        cursor.executemany('''
            INSERT INTO policies (name, policy_number, sensitive_info)
            VALUES (?, ?, ?)
        ''', policies)
        db.commit()
        db.close()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def home():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SecureLife Insurance</title>
    <link rel="stylesheet"
     href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
     integrity="sha384-..." crossorigin="anonymous">
</head>
<body>
    <div class="container mt-5">
        <h1>Welcome to SecureLife Insurance</h1>
        <p>Your trusted partner for life insurance.</p>
        <a href="/search" class="btn btn-primary">Search Policies</a>
    </div>
</body>
</html>
''')

@app.route('/search', methods=['GET', 'POST'])
def search():
    result = None
    message = ''
    col_names = []
    if request.method == 'POST':
        query = request.form['query']
        db = get_db()
        cursor = db.cursor()
        try:
            # Vulnerable query susceptible to SQL Injection
            cursor.execute("SELECT name, policy_number FROM policies WHERE name = '%s'" % query)
            result = cursor.fetchall()
            col_names = [description[0] for description in cursor.description]

            if 'sensitive_info' in col_names:
                message = 'Congratulations! You have found the sensitive data.'
        except Exception as e:
            result = []
            message = 'An error occurred.'

    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Policy Search - SecureLife Insurance</title>
    <link rel="stylesheet"
     href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
     integrity="sha384-..." crossorigin="anonymous">
</head>
<body>
    <div class="container mt-5">
        <h1>Policy Search</h1>
        <form method="post">
            <div class="mb-3">
                <label for="query" class="form-label">Policyholder Name</label>
                <input type="text" class="form-control" id="query" name="query" placeholder="Enter Name">
            </div>
            <button type="submit" class="btn btn-primary">Search</button>
        </form>

        {% if message %}
        <div class="alert alert-success mt-3" role="alert">
            {{ message }}
        </div>
        {% endif %}

        {% if result %}
        <h2 class="mt-4">Results:</h2>
        <table class="table table-bordered">
            <thead>
                <tr>
                    {% for col in col_names %}
                    <th>{{ col }}</th>
                    {% endfor %}
                </tr>
            </thead>
            <tbody>
                {% for row in result %}
                <tr>
                    {% for cell in row %}
                    <td>{{ cell }}</td>
                    {% endfor %}
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
    </div>
</body>
</html>
''', result=result, message=message, col_names=col_names)
if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)