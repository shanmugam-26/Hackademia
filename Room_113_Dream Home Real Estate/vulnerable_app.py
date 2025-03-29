from flask import Flask, request, make_response, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    properties = [
        {'id': 1, 'title': 'Luxury Villa', 'description': 'A beautiful villa by the sea.', 'image': 'https://via.placeholder.com/300'},
        {'id': 2, 'title': 'Urban Apartment', 'description': 'A modern apartment in the city center.', 'image': 'https://via.placeholder.com/300'},
        {'id': 3, 'title': 'Cozy Cottage', 'description': 'A cozy cottage in the countryside.', 'image': 'https://via.placeholder.com/300'}
    ]
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dream Home Real Estate</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            .header { background-color: #333; color: #fff; padding: 20px; text-align: center; }
            .nav { overflow: hidden; background-color: #333; }
            .nav a { float: left; display: block; color: #fff; text-align: center; padding: 14px 16px; text-decoration: none; }
            .nav a:hover { background-color: #ddd; color: black; }
            .content { padding: 20px; }
            .property { border: 1px solid #ccc; margin-bottom: 20px; padding: 10px; }
            .property img { max-width: 100%; height: auto; }
            .footer { background-color: #333; color: #fff; padding: 10px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Dream Home Real Estate</h1>
            <p>Your dream home awaits...</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/login">Login</a>
            <a href="/contact">Contact Us</a>
        </div>
        <div class="content">
            {% for property in properties %}
            <div class="property">
                <h2>{{ property.title }}</h2>
                <img src="{{ property.image }}" alt="{{ property.title }}">
                <p>{{ property.description }}</p>
                <a href="/property/{{ property.id }}">View Details</a>
            </div>
            {% endfor %}
        </div>
        <div class="footer">
            <p>&copy; 2023 Dream Home Real Estate</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html, properties=properties)

@app.route('/login', methods=['GET', 'POST'])
def login():
    html_form = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Dream Home Real Estate</title>
    </head>
    <body>
        <h1>Login</h1>
        <form action="/login" method="GET">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username"><br>
            <label for="password">Password:</label><br>
            <input type="text" id="password" name="password"><br><br>
            <input type="submit" value="Login">
        </form>
    </body>
    </html>
    '''
    if request.method == 'GET' and 'username' in request.args and 'password' in request.args:
        username = request.args.get('username')
        password = request.args.get('password')
        resp = make_response('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Welcome - Dream Home Real Estate</title>
        </head>
        <body>
            <h1>Welcome, {}</h1>
            <p>You are now logged in.</p>
            <a href="/">Go to Home</a>
        </body>
        </html>
        '''.format(username))
        resp.set_cookie('username', username)
        resp.set_cookie('role', 'user')
        return resp
    else:
        return html_form

@app.route('/admin')
def admin():
    role = request.cookies.get('role')
    if role == 'admin':
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel - Dream Home Real Estate</title>
        </head>
        <body>
            <h1>Admin Panel</h1>
            <p>Congratulations! You have found the hidden admin panel.</p>
        </body>
        </html>
        '''
    else:
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Denied - Dream Home Real Estate</title>
        </head>
        <body>
            <h1>Access Denied</h1>
            <p>You do not have permission to access this page.</p>
            <a href="/">Go to Home</a>
        </body>
        </html>
        '''

@app.route('/contact')
def contact():
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - Dream Home Real Estate</title>
    </head>
    <body>
        <h1>Contact Us</h1>
        <p>Phone: +1 (555) 123-4567</p>
        <p>Email: info@dreamhome.com</p>
        <a href="/">Go to Home</a>
    </body>
    </html>
    '''
    return html

@app.route('/property/<int:property_id>')
def property_detail(property_id):
    properties = {
        1: {'title': 'Luxury Villa', 'description': 'A beautiful villa by the sea.', 'image': 'https://via.placeholder.com/600'},
        2: {'title': 'Urban Apartment', 'description': 'A modern apartment in the city center.', 'image': 'https://via.placeholder.com/600'},
        3: {'title': 'Cozy Cottage', 'description': 'A cozy cottage in the countryside.', 'image': 'https://via.placeholder.com/600'}
    }
    property = properties.get(property_id)
    if property:
        html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ property.title }} - Dream Home Real Estate</title>
        </head>
        <body>
            <h1>{{ property.title }}</h1>
            <img src="{{ property.image }}" alt="{{ property.title }}">
            <p>{{ property.description }}</p>
            <a href="/">Go to Home</a>
        </body>
        </html>
        '''
        return render_template_string(html, property=property)
    else:
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Property Not Found - Dream Home Real Estate</title>
        </head>
        <body>
            <h1>Property Not Found</h1>
            <p>The property you are looking for does not exist.</p>
            <a href="/">Go to Home</a>
        </body>
        </html>
        '''

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)