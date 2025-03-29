from flask import Flask, render_template_string, request, redirect, url_for, abort

app = Flask(__name__)

# In-memory database for users
users = {}

# Secret API key (Sensitive data)
SECRET_API_KEY = '12345-SECRET-API-KEY-67890'

@app.route('/')
def index():
    # Render the main page (fitness center homepage)
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Elite Fitness Center</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
            header { background-color: #50b3a2; color: #fff; padding: 20px; text-align: center; }
            nav a { margin: 0 15px; color: #fff; text-decoration: none; }
            section { margin: 20px; }
            footer { background-color: #333; color: #fff; text-align: center; padding: 10px; }
        </style>
    </head>
    <body>
        <header>
            <h1>Welcome to Elite Fitness Center!</h1>
            <nav>
                <a href="{{ url_for('index') }}">Home</a>
                <a href="{{ url_for('register') }}">Register</a>
                <a href="{{ url_for('login') }}">Login</a>
                <a href="{{ url_for('contact') }}">Contact Us</a>
            </nav>
        </header>
        <section>
            <h2>Your health, our priority.</h2>
            <p>Join us for a journey to a healthier life.</p>
        </section>
        <footer>
            &copy; 2023 Elite Fitness Center
            <!-- TODO: Remove before deployment: Developer notes at /dev_notes.txt -->
        </footer>
    </body>
    </html>
    ''')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Handle registration
        username = request.form['username']
        password = request.form['password']
        users[username] = password
        return redirect(url_for('login'))
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - Elite Fitness Center</title>
    </head>
    <body>
        <h2>Register</h2>
        <form method="post">
            Username: <input name="username" type="text" required/><br />
            Password: <input name="password" type="password" required/><br />
            <input type="submit" value="Register" />
        </form>
        <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a>.</p>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            return redirect(url_for('dashboard', username=username))
        else:
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login - Elite Fitness Center</title>
            </head>
            <body>
                <h2>Login</h2>
                <p style="color:red;">Invalid credentials</p>
                <form method="post">
                    Username: <input name="username" type="text" required/><br />
                    Password: <input name="password" type="password" required/><br />
                    <input type="submit" value="Login" />
                </form>
            </body>
            </html>
            ''')
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - Elite Fitness Center</title>
    </head>
    <body>
        <h2>Login</h2>
        <form method="post">
            Username: <input name="username" type="text" required/><br />
            Password: <input name="password" type="password" required/><br />
            <input type="submit" value="Login" />
        </form>
        <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a>.</p>
    </body>
    </html>
    ''')

@app.route('/dashboard/<username>')
def dashboard(username):
    if username in users:
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - Elite Fitness Center</title>
        </head>
        <body>
            <h2>Welcome, {{ username }}!</h2>
            <p>This is your dashboard.</p>
        </body>
        </html>
        ''', username=username)
    else:
        return abort(403)

@app.route('/contact')
def contact():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - Elite Fitness Center</title>
    </head>
    <body>
        <h2>Contact Us</h2>
        <p>Email: support@elitefitness.com</p>
        <p>Phone: (123) 456-7890</p>
    </body>
    </html>
    ''')

# Serve the developer notes file (this simulates sensitive data exposure)
@app.route('/dev_notes.txt')
def dev_notes():
    # Intentional exposure of sensitive data
    return '''
    Developer Notes:

    - SECRET_API_KEY: {}

    - TODO: Secure the /admin panel with proper authentication

    - Remember to delete this file before deployment
    '''.format(SECRET_API_KEY)

@app.route('/admin')
def admin_panel():
    # Exposed admin panel without authentication
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
    </head>
    <body>
        <h2>Admin Panel</h2>
        <p>Welcome, admin!</p>
        <p>Users data: {}</p>
        <p style="color: green; font-weight: bold;">Congratulations! You have found the hidden admin panel.</p>
    </body>
    </html>
    '''.format(users)

# Run the Flask app
if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)