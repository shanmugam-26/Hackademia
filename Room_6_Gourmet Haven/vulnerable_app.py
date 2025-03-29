from flask import Flask, render_template_string, request, redirect, url_for, make_response, send_file
import os
import sqlite3
from werkzeug.utils import secure_filename
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'supersecretkey'

DATABASE = 'restaurant.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS reservations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        message TEXT
    )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Gourmet Haven</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f0f0f0; }
            .container { width: 60%; margin: auto; background-color: #fff; padding: 20px; }
            h1 { text-align: center; }
            form { display: flex; flex-direction: column; }
            input, textarea { margin-bottom: 10px; padding: 10px; font-size: 16px; }
            button { padding: 10px; font-size: 16px; background-color: #28a745; color: #fff; border: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to Gourmet Haven</h1>
            <p>Experience the finest dining with us. Reserve your table now!</p>
            <form action="/reserve" method="post">
                <input type="text" name="name" placeholder="Your Name" required />
                <input type="email" name="email" placeholder="Your Email" required />
                <input type="tel" name="phone" placeholder="Your Phone Number" required />
                <textarea name="message" placeholder="Special Requests"></textarea>
                <button type="submit">Reserve Now</button>
            </form>
        </div>
    </body>
    </html>
    ''')

@app.route('/reserve', methods=['POST'])
def reserve():
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    message = request.form['message']

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('INSERT INTO reservations (name, email, phone, message) VALUES (?, ?, ?, ?)',
              (name, email, phone, message))
    conn.commit()
    conn.close()

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Reservation Confirmed</title>
    </head>
    <body>
        <h1>Thank you for your reservation, {{ name }}!</h1>
        <p>We look forward to serving you at Gourmet Haven.</p>
        <a href="/">Back to Home</a>
    </body>
    </html>
    ''', name=name)

# Vulnerable endpoint exposing sensitive data
@app.route('/.config')
def get_config():
    # Intentionally exposing sensitive configuration data
    config_data = '''
    SECRET_KEY = 'supersecretkey'
    DATABASE_URI = 'sqlite:///restaurant.db'
    ADMIN_PASSWORD = 'admin123'
    FLAG = 'CONGRATULATIONS_YOU_FOUND_THE_SENSITIVE_DATA'
    '''
    response = make_response(config_data)
    response.headers['Content-Type'] = 'text/plain'
    return response

# Handle robots.txt which disallows certain directories
@app.route('/robots.txt')
def robots():
    robots_txt = '''
    User-agent: *
    Disallow: /admin
    Disallow: /.config
    '''
    response = make_response(robots_txt)
    response.headers['Content-Type'] = 'text/plain'
    return response

# Mock admin panel
@app.route('/admin')
def admin():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
    </head>
    <body>
        <h1>Admin Login</h1>
        <form action="/admin/login" method="post">
            <input type="password" name="password" placeholder="Enter admin password" required />
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    ''')

@app.route('/admin/login', methods=['POST'])
def admin_login():
    password = request.form['password']
    if password == 'admin123':
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT * FROM reservations')
        reservations = c.fetchall()
        conn.close()
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Dashboard</title>
        </head>
        <body>
            <h1>Reservation List</h1>
            <table border="1">
                <tr><th>ID</th><th>Name</th><th>Email</th><th>Phone</th><th>Message</th></tr>
                {% for res in reservations %}
                <tr>
                    <td>{{ res[0] }}</td>
                    <td>{{ res[1] }}</td>
                    <td>{{ res[2] }}</td>
                    <td>{{ res[3] }}</td>
                    <td>{{ res[4] }}</td>
                </tr>
                {% endfor %}
            </table>
            <p>Flag: CONGRATULATIONS_YOU_LOGGED_IN_AS_ADMIN</p>
        </body>
        </html>
        ''', reservations=reservations)
    else:
        return redirect(url_for('admin'))

@app.route('/sitemap.xml')
def sitemap():
    sitemap_xml = '''
    <?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
       <url>
          <loc>http://localhost:5000/</loc>
          <priority>1.00</priority>
       </url>
       <url>
          <loc>http://localhost:5000/reserve</loc>
          <priority>0.80</priority>
       </url>
    </urlset>
    '''
    response = make_response(sitemap_xml)
    response.headers['Content-Type'] = 'application/xml'
    return response

if __name__ == '__main__':
    init_db()
    app.run(debug=True)