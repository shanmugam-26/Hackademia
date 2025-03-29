from flask import Flask, render_template_string, request, send_file, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

# Initialize a mock database
def init_db():
    conn = sqlite3.connect('properties.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS properties
                 (id INTEGER PRIMARY KEY, name TEXT, description TEXT, price TEXT, image TEXT)''')
    properties = [
        (1, 'Sunnyvale Villa', 'A beautiful villa with sunny views.', '$1,200,000', 'villa.jpg'),
        (2, 'Downtown Apartment', 'Modern apartment in the heart of the city.', '$850,000', 'apartment.jpg'),
        (3, 'Suburban House', 'A cozy house in the suburbs.', '$600,000', 'house.jpg')
    ]
    c.executemany('INSERT OR IGNORE INTO properties VALUES (?, ?, ?, ?, ?)', properties)
    conn.commit()
    conn.close()

# Route for the main page
@app.route("/")
def index():
    conn = sqlite3.connect('properties.db')
    c = conn.cursor()
    c.execute("SELECT * FROM properties")
    properties = c.fetchall()
    conn.close()
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>DreamHome Real Estate Agency</title>
        <style>
            body {font-family: Arial, sans-serif; margin: 0; padding: 0;}
            .header {background-color: #35424a; color: #ffffff; padding: 20px;}
            .container {padding: 20px;}
            .property {border: 1px solid #dddddd; padding: 10px; margin-bottom: 20px;}
            .property img {max-width: 100%;}
            .footer {background-color: #35424a; color: #ffffff; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>DreamHome Real Estate Agency</h1>
            <p>Your dream home is just a click away!</p>
        </div>
        <div class="container">
            {% for property in properties %}
            <div class="property">
                <h2>{{ property[1] }}</h2>
                <img src="/static/{{ property[4] }}" alt="{{ property[1] }}">
                <p>{{ property[2] }}</p>
                <p>Price: {{ property[3] }}</p>
                <a href="/property?id={{ property[0] }}">More Details</a>
            </div>
            {% endfor %}
        </div>
        <div class="footer">
            &copy; 2023 DreamHome Real Estate Agency
        </div>
    </body>
    </html>
    '''
    return render_template_string(html, properties=properties)

# Route for property details
@app.route("/property")
def property_detail():
    property_id = request.args.get('id')
    conn = sqlite3.connect('properties.db')
    c = conn.cursor()
    c.execute("SELECT * FROM properties WHERE id = ?", (property_id,))
    property = c.fetchone()
    conn.close()
    if property:
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ property[1] }} - DreamHome</title>
            <style>
                body {font-family: Arial, sans-serif; margin: 0; padding: 0;}
                .header {background-color: #35424a; color: #ffffff; padding: 20px;}
                .container {padding: 20px;}
                .footer {background-color: #35424a; color: #ffffff; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%;}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ property[1] }}</h1>
            </div>
            <div class="container">
                <img src="/static/{{ property[4] }}" alt="{{ property[1] }}">
                <p>{{ property[2] }}</p>
                <p>Price: {{ property[3] }}</p>
                <p><a href="/">Back to Listings</a></p>
            </div>
            <div class="footer">
                &copy; 2023 DreamHome Real Estate Agency
            </div>
        </body>
        </html>
        '''
        return render_template_string(html, property=property)
    else:
        return redirect(url_for('index'))

# Vulnerable route exposing sensitive data
@app.route('/api/clients')
def clients():
    # Intentional vulnerability: Exposing client data without authentication
    client_info = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Client Information</title>
    </head>
    <body>
        <h1>Confidential Client List</h1>
        <ul>
            <li>John Doe - john.doe@example.com</li>
            <li>Jane Smith - jane.smith@example.com</li>
            <li>Alice Johnson - alice.johnson@example.com</li>
        </ul>
        <p>Congratulations! You have found the sensitive data exposure vulnerability!</p>
    </body>
    </html>
    '''
    return client_info

# Serve static files
@app.route('/static/<path:path>')
def send_static(path):
    return send_file(os.path.join('static', path))

if __name__ == '__main__':
    if not os.path.exists('properties.db'):
        init_db()
    if not os.path.exists('static'):
        os.makedirs('static')
        # Add placeholder images
        with open('static/villa.jpg', 'wb') as f:
            f.write(b'')  # Empty file for placeholder
        with open('static/apartment.jpg', 'wb') as f:
            f.write(b'')
        with open('static/house.jpg', 'wb') as f:
            f.write(b'')
    app.run(debug=False)