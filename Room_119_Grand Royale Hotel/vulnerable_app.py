from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

def init_db():
    if not os.path.exists('hotel.db'):
        conn = sqlite3.connect('hotel.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            );
        ''')
        # Insert sample users
        c.executemany('''
            INSERT INTO users (username, password) VALUES (?, ?)
        ''', [
            ('guest', 'guestpass'),
            ('user', 'userpass'),
            ('admin', 'adminpass'),
        ])
        conn.commit()
        conn.close()

@app.route('/')
def home():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grand Royale Hotel</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
        .header { text-align: center; padding: 50px; background-image: url('https://via.placeholder.com/1500x500'); background-size: cover; color: white; }
        .header h1 { font-size: 50px; margin: 0; }
        .header p { font-size: 20px; }
        .nav { text-align: center; margin-top: 20px; }
        .nav a { margin: 0 15px; text-decoration: none; color: #333; font-weight: bold; }
        .nav a:hover { color: #007BFF; }
        .content { max-width: 800px; margin: auto; padding: 20px; background-color: white; }
        .footer { text-align: center; padding: 10px; background-color: #333; color: white; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to Grand Royale Hotel</h1>
        <p>Your luxury stay awaits</p>
    </div>
    <div class="nav">
        <a href="{{ url_for('home') }}">Home</a>
        <a href="{{ url_for('login') }}">Login</a>
        <a href="#">Rooms</a>
        <a href="#">Dining</a>
        <a href="#">Spa</a>
        <a href="#">Contact Us</a>
    </div>
    <div class="content">
        <h2>About Us</h2>
        <p>Welcome to the Grand Royale Hotel, where luxury meets comfort. Nestled in the heart of the city, our hotel offers world-class amenities and exceptional service to make your stay unforgettable.</p>
        <h2>Our Rooms</h2>
        <p>Experience the epitome of luxury in our elegantly designed rooms and suites that offer breathtaking views of the city skyline.</p>
        <h2>Fine Dining</h2>
        <p>Savor exquisite cuisines from around the world in our award-winning restaurants.</p>
        <h2>Spa & Wellness</h2>
        <p>Rejuvenate your senses with our exclusive spa treatments and wellness programs.</p>
    </div>
    <div class="footer">
        &copy; 2023 Grand Royale Hotel. All rights reserved.
    </div>
</body>
</html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('hotel.db')
        c = conn.cursor()
        query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(username, password)
        c.execute(query)
        result = c.fetchone()
        conn.close()
        if result:
            if username == 'admin':
                return redirect(url_for('admin'))
            else:
                error = 'Access denied. Administrators only.'
        else:
            error = 'Invalid credentials.'
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grand Royale Hotel - Login</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
        .header { text-align: center; padding: 50px; background-color: #007BFF; color: white; }
        .header h1 { font-size: 50px; margin: 0; }
        .nav { text-align: center; margin-top: 20px; }
        .nav a { margin: 0 15px; text-decoration: none; color: #333; font-weight: bold; }
        .nav a:hover { color: #007BFF; }
        .content { max-width: 400px; margin: auto; padding: 20px; background-color: white; margin-top: 50px; border-radius: 5px; }
        .error { color: red; text-align: center; }
        .login-form { text-align: center; }
        .login-form input[type="text"], .login-form input[type="password"] { padding: 10px; margin: 5px; width: 80%; }
        .login-form input[type="submit"] { padding: 10px 20px; margin-top: 10px; background-color: #007BFF; color: white; border: none; cursor: pointer; }
        .login-form input[type="submit"]:hover { background-color: #0056b3; }
        .footer { text-align: center; padding: 10px; background-color: #333; color: white; margin-top: 20px; position: fixed; width: 100%; bottom: 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Administrator Login</h1>
    </div>
    <div class="nav">
        <a href="{{ url_for('home') }}">Home</a>
        <a href="{{ url_for('login') }}">Login</a>
    </div>
    <div class="content">
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post" class="login-form">
            <input type="text" name="username" placeholder="Username" required /><br />
            <input type="password" name="password" placeholder="Password" required /><br />
            <input type="submit" value="Login" />
        </form>
    </div>
    <div class="footer">
        &copy; 2023 Grand Royale Hotel. All rights reserved.
    </div>
</body>
</html>
    ''', error=error)

@app.route('/admin')
def admin():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Grand Royale Hotel - Admin Panel</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #333; color: white; margin: 0; }
        .header { text-align: center; padding: 50px; background-color: #222; }
        .header h1 { font-size: 50px; margin: 0; }
        .content { max-width: 600px; margin: auto; padding: 20px; background-color: #444; margin-top: 50px; border-radius: 5px; text-align: center; }
        .content h2 { color: #00FF00; }
        .footer { text-align: center; padding: 10px; background-color: #222; position: fixed; width: 100%; bottom: 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Administrator Panel</h1>
    </div>
    <div class="content">
        <h2>Congratulations!</h2>
        <p>You have successfully accessed the administrator panel.</p>
        <p>Your skills are impressive.</p>
    </div>
    <div class="footer">
        &copy; 2023 Grand Royale Hotel. All rights reserved.
    </div>
</body>
</html>
    ''')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)