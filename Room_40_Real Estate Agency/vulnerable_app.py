from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

# Security Misconfiguration: Debug mode is left on in production
app.config['DEBUG'] = True

# Function to initialize the database
def init_db():
    conn = sqlite3.connect('properties.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS properties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL,
            image_url TEXT NOT NULL
        )
    ''')
    # Insert sample data if the table is empty
    c.execute('SELECT COUNT(*) FROM properties')
    if c.fetchone()[0] == 0:
        properties = [
            ('Luxury Villa', 'A beautiful villa by the sea.', 1000000, 'https://via.placeholder.com/400x300'),
            ('City Apartment', 'Modern apartment in the city center.', 500000, 'https://via.placeholder.com/400x300'),
            ('Cozy Cottage', 'A quaint cottage in the countryside.', 250000, 'https://via.placeholder.com/400x300')
        ]
        c.executemany('INSERT INTO properties (title, description, price, image_url) VALUES (?, ?, ?, ?)', properties)
        conn.commit()
    return conn

# Initialize the database
conn = init_db()

# Ensure the templates directory exists
if not os.path.exists('templates'):
    os.makedirs('templates')

# Create the index.html template
with open('templates/index.html', 'w') as f:
    f.write('''
    {% extends "layout.html" %}
    {% block content %}
    <h1 class="mt-4">Properties for Sale</h1>
    <div class="row">
        {% for property in properties %}
        <div class="col-md-4">
            <div class="card mb-4 shadow-sm">
                <img src="{{ property[4] }}" class="card-img-top" alt="{{ property[1] }}">
                <div class="card-body">
                    <h5 class="card-title">{{ property[1] }}</h5>
                    <p class="card-text">{{ property[2][:100] }}...</p>
                    <div class="d-flex justify-content-between align-items-center">
                        <a href="{{ url_for('property_detail', id=property[0]) }}" class="btn btn-sm btn-outline-secondary">View Details</a>
                        <small class="text-muted">${{ '{:,.2f}'.format(property[3]) }}</small>
                    </div>
                </div>
            </div>
        </div>
        {% endfor %}
    </div>
    {% endblock %}
    ''')

# Create the property_detail.html template
with open('templates/property_detail.html', 'w') as f:
    f.write('''
    {% extends "layout.html" %}
    {% block content %}
    <h1 class="mt-4">{{ property[1] }}</h1>
    <img src="{{ property[4] }}" class="img-fluid mb-4" alt="{{ property[1] }}">
    <p>{{ property[2] }}</p>
    <h4>Price: ${{ '{:,.2f}'.format(property[3]) }}</h4>
    <a href="{{ url_for('index') }}" class="btn btn-secondary mt-4">Back to Properties</a>
    {% endblock %}
    ''')

# Create the admin.html template
with open('templates/admin.html', 'w') as f:
    f.write('''
    {% extends "layout.html" %}
    {% block content %}
    <h1 class="mt-4">Admin Panel</h1>
    <a href="{{ url_for('add_property') }}" class="btn btn-primary mb-3">Add New Property</a>
    <table class="table table-bordered">
        <thead class="thead-dark">
            <tr>
                <th>ID</th>
                <th>Title</th>
                <th>Description</th>
                <th>Price</th>
                <th>Image URL</th>
            </tr>
        </thead>
        <tbody>
            {% for property in properties %}
            <tr>
                <td>{{ property[0] }}</td>
                <td>{{ property[1] }}</td>
                <td>{{ property[2][:50] }}...</td>
                <td>${{ '{:,.2f}'.format(property[3]) }}</td>
                <td>{{ property[4] }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endblock %}
    ''')

# Create the add_property.html template
with open('templates/add_property.html', 'w') as f:
    f.write('''
    {% extends "layout.html" %}
    {% block content %}
    <h1 class="mt-4">Add New Property</h1>
    <form method="post">
        <div class="form-group">
            <label for="title">Property Title</label>
            <input type="text" class="form-control" id="title" name="title" required>
        </div>
        <div class="form-group">
            <label for="description">Property Description</label>
            <textarea class="form-control" id="description" name="description" rows="5" required></textarea>
        </div>
        <div class="form-group">
            <label for="price">Property Price</label>
            <input type="number" class="form-control" id="price" name="price" required>
        </div>
        <div class="form-group">
            <label for="image_url">Property Image URL</label>
            <input type="url" class="form-control" id="image_url" name="image_url" required>
        </div>
        <button type="submit" class="btn btn-success">Add Property</button>
        <a href="{{ url_for('admin') }}" class="btn btn-secondary">Cancel</a>
    </form>
    {% endblock %}
    ''')

# Create the layout.html template for consistent styling
with open('templates/layout.html', 'w') as f:
    f.write('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Real Estate Agency</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
        <style>
            body {
                padding-top: 56px;
            }
        </style>
    </head>
    <body>
        <!-- Navigation -->
        <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
            <a class="navbar-brand" href="{{ url_for('index') }}">Real Estate Agency</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarsExampleDefault" aria-controls="navbarsExampleDefault" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>
    
            <div class="collapse navbar-collapse" id="navbarsExampleDefault">
                <ul class="navbar-nav ml-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('index') }}">Home</a>
                    </li>
                    <!-- Admin link is intentionally exposed -->
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('admin') }}">Admin</a>
                    </li>
                </ul>
            </div>
        </nav>
    
        <main role="main" class="container">
            {% with messages = get_flashed_messages() %}
              {% if messages %}
                {% for message in messages %}
                  <div class="alert alert-warning" role="alert">
                    {{ message }}
                  </div>
                {% endfor %}
              {% endif %}
            {% endwith %}
            {% block content %}{% endblock %}
        </main>
    
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    ''')

# Route for the home page
@app.route('/')
def index():
    c = conn.cursor()
    c.execute('SELECT * FROM properties')
    properties = c.fetchall()
    return render_template('index.html', properties=properties)

# Route for property details
@app.route('/property/<int:id>')
def property_detail(id):
    c = conn.cursor()
    c.execute('SELECT * FROM properties WHERE id = ?', (id,))
    property = c.fetchone()
    return render_template('property_detail.html', property=property)

# Security Misconfiguration: Exposed admin panel without authentication
@app.route('/admin')
def admin():
    c = conn.cursor()
    c.execute('SELECT * FROM properties')
    properties = c.fetchall()
    return render_template('admin.html', properties=properties)

# Route to add new properties via the admin panel
@app.route('/admin/add', methods=['GET', 'POST'])
def add_property():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = float(request.form['price'])
        image_url = request.form['image_url']
        c = conn.cursor()
        c.execute('INSERT INTO properties (title, description, price, image_url) VALUES (?, ?, ?, ?)',
                  (title, description, price, image_url))
        conn.commit()
        return redirect(url_for('admin'))
    return render_template('add_property.html')

# 'Congratulations' route for students who find the vulnerability
@app.route('/congratulations')
def congratulations():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Congratulations!</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    </head>
    <body>
        <div class="container text-center mt-5">
            <h1>Congratulations!</h1>
            <p>You have found the security vulnerability.</p>
        </div>
    </body>
    </html>
    '''

# Run the Flask application
if __name__ == '__main__':
    app.run()