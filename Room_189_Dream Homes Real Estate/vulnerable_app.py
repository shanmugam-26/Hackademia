from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

# Initialize the database
def init_db():
    conn = sqlite3.connect('realestate.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS properties
                 (id INTEGER PRIMARY KEY, name TEXT, location TEXT, price INTEGER)''')
    # Insert some sample data if it doesn't exist
    c.execute("SELECT COUNT(*) FROM properties")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO properties (id, name, location, price) VALUES (1, 'Modern Apartment', 'New York', 2000000)")
        c.execute("INSERT INTO properties (id, name, location, price) VALUES (2, 'Cozy Cottage', 'Los Angeles', 1500000)")
        c.execute("INSERT INTO properties (id, name, location, price) VALUES (3, 'Beach House', 'Miami', 3000000)")
    # Hidden admin table
    c.execute('''CREATE TABLE IF NOT EXISTS admin
                 (id INTEGER PRIMARY KEY, secret TEXT)''')
    c.execute("SELECT COUNT(*) FROM admin")
    if c.fetchone()[0] == 0:
        c.execute("INSERT INTO admin (id, secret) VALUES (1, 'Congratulations! You have successfully exploited the SQL Injection vulnerability.')")
    conn.commit()
    conn.close()

init_db()

index_template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Dream Homes Real Estate</title>
  <link rel="stylesheet"
        href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
  <style>
      body { background-color: #f8f9fa; }
      .property-card { margin: 20px; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="/">Dream Homes Real Estate</a>
</nav>
<div class="container">
  <h1 class="mt-4">Find Your Dream Home</h1>
  <form method="get" action="/search">
    <div class="form-group">
      <label for="location">Search by Location</label>
      <input type="text" class="form-control" id="location" name="location"
             placeholder="Enter city">
    </div>
    <button type="submit" class="btn btn-primary">Search</button>
  </form>
  <div class="mt-4">
    {%- if properties %}
      <h2>Results:</h2>
      <div class="row">
      {%- for property in properties %}
        <div class="col-sm-4">
          <div class="card property-card">
            <div class="card-body">
              <h5 class="card-title">{{ property[1] }}</h5>
              <p class="card-text">Location: {{ property[2] }}</p>
              <p class="card-text">Price: ${{ property[3] }}</p>
            </div>
          </div>
        </div>
      {%- endfor %}
      </div>
    {%- else %}
      {%- if searched %}
        <p>No properties found at that location.</p>
      {%- endif %}
    {%- endif %}
    {%- if secret_message %}
      <div class="alert alert-success mt-4" role="alert">
        {{ secret_message }}
      </div>
    {%- endif %}
  </div>
</div>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(index_template, properties=None, searched=False)

@app.route('/search')
def search():
    location = request.args.get('location', '')
    conn = sqlite3.connect('realestate.db')
    c = conn.cursor()
    query = "SELECT * FROM properties WHERE location = '{}';".format(location)
    try:
        c.execute(query)
        properties = c.fetchall()
    except Exception as e:
        properties = []
    # Check for secret message
    secret_message = None
    if properties:
        for prop in properties:
            if prop[1] == 'Congratulations':
                secret_message = prop[2]
                properties.remove(prop)
                break
    conn.close()
    return render_template_string(index_template, properties=properties, searched=True, secret_message=secret_message)
if __name__ == '__main__':
      app.run(debug=True)