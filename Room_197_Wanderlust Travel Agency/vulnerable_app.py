from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Initialize the database
def init_db():
    conn = sqlite3.connect('travel.db')
    cursor = conn.cursor()
    # Create a table for travel packages
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            destination TEXT,
            description TEXT,
            price REAL
        )
    ''')
    # Insert some sample data
    cursor.execute("INSERT INTO packages (destination, description, price) VALUES ('Paris', 'Visit the Eiffel Tower', 1200)")
    cursor.execute("INSERT INTO packages (destination, description, price) VALUES ('New York', 'See the Statue of Liberty', 1500)")
    cursor.execute("INSERT INTO packages (destination, description, price) VALUES ('Tokyo', 'Experience the vibrant city life', 1800)")
    
    # Create a table for secrets
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            secret TEXT
        )
    ''')
    # Insert secret data
    cursor.execute("INSERT INTO secrets (secret) VALUES ('Congratulations! You have successfully exploited the SQL Injection vulnerability.')")
    
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    homepage_html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Wanderlust Travel Agency</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
    <div class="container">
        <h1 class="mt-5">Welcome to Wanderlust Travel Agency</h1>
        <p>Your journey begins here. Explore our destinations:</p>
        <form action="/search" method="GET">
            <div class="mb-3">
                <label for="destination" class="form-label">Search Destinations</label>
                <input type="text" class="form-control" id="destination" name="destination" placeholder="Enter a destination">
            </div>
            <button type="submit" class="btn btn-primary">Search</button>
        </form>
    </div>
    </body>
    </html>
    '''
    return render_template_string(homepage_html)

@app.route('/search')
def search():
    destination = request.args.get('destination')
    query = "SELECT * FROM packages WHERE destination = '{}'".format(destination)
    conn = sqlite3.connect('travel.db')
    cursor = conn.cursor()
    try:
        cursor.execute(query)
        results = cursor.fetchall()
    except Exception as e:
        return "An error occurred: {}".format(e)
    conn.close()
    
    # Render the results
    search_results_html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Search Results - Wanderlust Travel Agency</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
    <div class="container">
        <h1 class="mt-5">Search Results</h1>
        <p>Showing results for "{{destination}}":</p>
        {% if results %}
            <ul class="list-group">
            {% for row in results %}
                <li class="list-group-item">
                    <h5>{{row[1]}}</h5>
                    <p>{{row[2]}}</p>
                    <p>Price: ${{row[3]}}</p>
                </li>
            {% endfor %}
            </ul>
        {% else %}
            <p>No packages found for "{{destination}}".</p>
        {% endif %}
    </div>
    </body>
    </html>
    '''
    
    # Check if secrets data is in results
    for row in results:
        if 'Congratulations' in str(row):
            return '<h1>{}</h1>'.format(row[1])
    
    return render_template_string(search_results_html, destination=destination, results=results)
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)