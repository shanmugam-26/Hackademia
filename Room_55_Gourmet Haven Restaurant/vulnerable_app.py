from flask import Flask, render_template_string, request, redirect, url_for, make_response, jsonify, Response
import os
import random
import string

app = Flask(__name__)

# Mock database of users
users = {'admin': 'supersecretpassword'}

# Function to simulate complex operations
def complex_operation():
    data = ''.join(random.choices(string.ascii_letters + string.digits, k=1000))
    return data

# Home page route
@app.route('/')
def home():
    featured_item = request.args.get('item', 'Chef\'s Special')
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Gourmet Haven Restaurant</title>
        <style>
            body { font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; background-color: #fdfdfd; }
            header { background-color: #2d3e50; padding: 20px; text-align: center; }
            header h1 { color: white; margin: 0; }
            nav { background-color: #1abc9c; }
            nav ul { list-style-type: none; margin: 0; padding: 0; overflow: hidden; }
            nav li { float: left; }
            nav li a { display: block; color: white; text-align: center; padding: 14px 16px; text-decoration: none; }
            nav li a:hover { background-color: #16a085; }
            .content { padding: 20px; }
            footer { background-color: #2d3e50; color: white; text-align: center; padding: 10px; position: relative; bottom: 0; width: 100%; }
        </style>
    </head>
    <body>
        <header>
            <h1>Welcome to Gourmet Haven!</h1>
        </header>
        <nav>
            <ul>
                <li><a href="{{ url_for('home') }}">Home</a></li>
                <li><a href="{{ url_for('menu') }}">Menu</a></li>
                <li><a href="{{ url_for('reservations') }}">Reservations</a></li>
                <li><a href="{{ url_for('contact') }}">Contact</a></li>
                <li><a href="{{ url_for('login') }}">Admin</a></li>
            </ul>
        </nav>
        <div class="content">
            <h2>About Us</h2>
            <p>Experience the finest dining with our exquisite dishes made from the freshest ingredients.</p>
            <h3>Today's Featured Item: {{ featured_item }}</h3>
        </div>
        <footer>
            &copy; 2023 Gourmet Haven. All rights reserved.
        </footer>
    </body>
    </html>
    ''', featured_item=featured_item)

# Menu page route
@app.route('/menu')
def menu():
    dishes = [
        {'name': 'Truffle Pasta', 'price': '$25'},
        {'name': 'Wagyu Steak', 'price': '$50'},
        {'name': 'Lobster Bisque', 'price': '$30'},
    ]
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Our Menu - Gourmet Haven</title>
        <!-- (Same styles as before) -->
    </head>
    <body>
        <!-- (Header and nav) -->
        <header>
            <h1>Our Menu</h1>
        </header>
        <nav>
            <ul>
                <li><a href="{{ url_for('home') }}">Home</a></li>
                <li><a href="{{ url_for('menu') }}">Menu</a></li>
                <li><a href="{{ url_for('reservations') }}">Reservations</a></li>
                <li><a href="{{ url_for('contact') }}">Contact</a></li>
                <li><a href="{{ url_for('login') }}">Admin</a></li>
            </ul>
        </nav>
        <div class="content">
            <h2>Our Dishes</h2>
            <ul>
                {% for dish in dishes %}
                <li>{{ dish.name }} - {{ dish.price }}</li>
                {% endfor %}
            </ul>
        </div>
        <footer>
            &copy; 2023 Gourmet Haven. All rights reserved.
        </footer>
    </body>
    </html>
    ''', dishes=dishes)

# Reservations page route
@app.route('/reservations', methods=['GET', 'POST'])
def reservations():
    if request.method == 'POST':
        # Process reservation
        name = request.form.get('name')
        email = request.form.get('email')
        date = request.form.get('date')
        # Save reservation data (simulated)
        reservation_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        # Expose sensitive data (vulnerability)
        response = make_response(redirect(url_for('reservation_confirmation', res_id=reservation_id)))
        # Store reservation data in cookie (vulnerability)
        response.set_cookie('reservation_data', f'{name},{email},{date}')
        return response
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Reservations - Gourmet Haven</title>
        <!-- (Same styles as before) -->
    </head>
    <body>
        <!-- (Header and nav) -->
        <header>
            <h1>Make a Reservation</h1>
        </header>
        <nav>
            <ul>
                <li><a href="{{ url_for('home') }}">Home</a></li>
                <li><a href="{{ url_for('menu') }}">Menu</a></li>
                <li><a href="{{ url_for('reservations') }}">Reservations</a></li>
                <li><a href="{{ url_for('contact') }}">Contact</a></li>
                <li><a href="{{ url_for('login') }}">Admin</a></li>
            </ul>
        </nav>
        <div class="content">
            <h2>Reserve Your Table</h2>
            <form method="post" action="{{ url_for('reservations') }}">
                <label for="name">Name:</label><br/>
                <input type="text" id="name" name="name"/><br/>
                <label for="email">Email:</label><br/>
                <input type="email" id="email" name="email"/><br/>
                <label for="date">Date:</label><br/>
                <input type="date" id="date" name="date"/><br/><br/>
                <input type="submit" value="Reserve"/>
            </form>
        </div>
        <footer>
            &copy; 2023 Gourmet Haven. All rights reserved.
        </footer>
    </body>
    </html>
    ''')

# Reservation confirmation
@app.route('/reservation_confirmation')
def reservation_confirmation():
    res_id = request.args.get('res_id')
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Reservation Confirmed - Gourmet Haven</title>
        <!-- (Same styles as before) -->
    </head>
    <body>
        <header>
            <h1>Reservation Confirmed</h1>
        </header>
        <nav>
            <ul>
                <li><a href="{{ url_for('home') }}">Home</a></li>
                <li><a href="{{ url_for('menu') }}">Menu</a></li>
                <li><a href="{{ url_for('reservations') }}">Reservations</a></li>
                <li><a href="{{ url_for('contact') }}">Contact</a></li>
                <li><a href="{{ url_for('login') }}">Admin</a></li>
            </ul>
        </nav>
        <div class="content">
            <h2>Your reservation is confirmed!</h2>
            <p>Your reservation ID is: {{ res_id }}</p>
        </div>
        <footer>
            &copy; 2023 Gourmet Haven. All rights reserved.
        </footer>
    </body>
    </html>
    ''', res_id=res_id)

# Contact page route
@app.route('/contact')
def contact():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - Gourmet Haven</title>
        <!-- (Same styles as before) -->
    </head>
    <body>
        <!-- (Header and nav) -->
        <header>
            <h1>Contact Us</h1>
        </header>
        <nav>
            <ul>
                <li><a href="{{ url_for('home') }}">Home</a></li>
                <li><a href="{{ url_for('menu') }}">Menu</a></li>
                <li><a href="{{ url_for('reservations') }}">Reservations</a></li>
                <li><a href="{{ url_for('contact') }}">Contact</a></li>
                <li><a href="{{ url_for('login') }}">Admin</a></li>
            </ul>
        </nav>
        <div class="content">
            <h2>We're Here to Help</h2>
            <p>Email: support@gourmethaven.com</p>
            <p>Phone: +1 (555) 987-6543</p>
            <p>Address: 456 Culinary Ave, Food City, CA</p>
        </div>
        <footer>
            &copy; 2023 Gourmet Haven. All rights reserved.
        </footer>
    </body>
    </html>
    ''')

# Admin login route
@app.route('/admin')
def admin():
    # Check if user is authenticated
    auth_token = request.cookies.get('auth_token')
    if auth_token == 'admin_authenticated':
        # Expose sensitive data (vulnerability)
        secret_data = 'Congratulations! You have accessed the admin panel. The secret key is FLAG{SensitiveDataExposure}'
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel - Gourmet Haven</title>
            <!-- (Same styles as before) -->
        </head>
        <body>
            <!-- (Header and nav) -->
            <header>
                <h1>Admin Panel</h1>
            </header>
            <nav>
                <ul>
                    <li><a href="{{ url_for('home') }}">Home</a></li>
                    <li><a href="{{ url_for('logout') }}">Logout</a></li>
                </ul>
            </nav>
            <div class="content">
                <h2>Secret Information</h2>
                <p>{{ secret_data }}</p>
            </div>
            <footer>
                &copy; 2023 Gourmet Haven. All rights reserved.
            </footer>
        </body>
        </html>
        ''', secret_data=secret_data)
    else:
        return redirect(url_for('login'))

# Login page route
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Insecure authentication (vulnerability)
        if username in users and users[username] == password:
            resp = make_response(redirect(url_for('admin')))
            # Insecurely set auth token (vulnerability)
            resp.set_cookie('auth_token', 'admin_authenticated')
            return resp
        else:
            error = 'Invalid credentials'
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login - Gourmet Haven</title>
        <!-- (Same styles as before) -->
    </head>
    <body>
        <!-- (Header and nav) -->
        <header>
            <h1>Admin Login</h1>
        </header>
        <nav>
            <ul>
                <li><a href="{{ url_for('home') }}">Home</a></li>
                <li><a href="{{ url_for('login') }}">Admin</a></li>
            </ul>
        </nav>
        <div class="content">
            <h2>Login</h2>
            <form method="post" action="{{ url_for('login') }}">
                <label for="username">Username:</label><br/>
                <input type="text" id="username" name="username"/><br/>
                <label for="password">Password:</label><br/>
                <input type="password" id="password" name="password"/><br/><br/>
                <input type="submit" value="Login"/>
            </form>
            <p style="color:red;">{{ error }}</p>
        </div>
        <footer>
            &copy; 2023 Gourmet Haven. All rights reserved.
        </footer>
    </body>
    </html>
    ''', error=error)

# Logout route
@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('home')))
    resp.set_cookie('auth_token', '', expires=0)
    return resp

# API endpoint that leaks sensitive info (vulnerability)
@app.route('/api/orders')
def api_orders():
    # Simulate order data
    orders = [
        {'order_id': 'ORD123', 'item': 'Truffle Pasta', 'customer': 'Alice'},
        {'order_id': 'ORD124', 'item': 'Wagyu Steak', 'customer': 'Bob'},
        {'order_id': 'ORD125', 'item': 'Lobster Bisque', 'customer': 'Charlie'},
    ]
    # Expose internal data (vulnerability)
    return jsonify(orders)

# Debug info route (vulnerability)
@app.route('/debug')
def debug():
    # Expose environment variables (vulnerability)
    env_vars = dict(os.environ)
    return jsonify(env_vars)

# Static file serving that reveals .env file (vulnerability)
@app.route('/.env')
def env_file():
    # Expose .env file contents (vulnerability)
    env_data = '''
SECRET_KEY=supersecretkey
DB_PASSWORD=admin123
API_KEY=abcdefg1234567
'''
    return Response(env_data, mimetype='text/plain')

# Start the Flask app
if __name__ == '__main__':
    app.run(debug=True)