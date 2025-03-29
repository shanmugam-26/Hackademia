from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

# Main landing page template
main_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Nova Consulting Group</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
        header { background-color: #2C3E50; color: white; padding: 20px; text-align: center; }
        nav { background-color: #34495E; overflow: hidden; }
        nav a { float: left; color: white; padding: 14px 16px; text-decoration: none; text-align: center; }
        nav a:hover { background-color: #2C3E50; }
        .hero { background-image: url('https://via.placeholder.com/1200x400'); height: 400px; background-size: cover; position: relative; }
        .hero-text { text-align: center; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: white; }
        .content { padding: 20px; }
        footer { background-color: #2C3E50; color: white; text-align: center; padding: 10px 0; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <header>
        <h1>Nova Consulting Group</h1>
        <p>Innovate. Strategize. Execute.</p>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/services">Services</a>
        <a href="/login">Client Login</a>
        <a href="/contact">Contact</a>
    </nav>
    <div class="hero">
        <div class="hero-text">
            <h2>Leading the Way in Business Consulting</h2>
            <p>Your success is our mission.</p>
        </div>
    </div>
    <div class="content">
        <h2>Welcome to Nova Consulting Group</h2>
        <p>
            At Nova Consulting Group, we provide top-tier business consulting services to help companies 
            navigate the complexities of today's market. Our team of experts leverages industry insights 
            and innovative strategies to drive growth and efficiency.
        </p>
    </div>
    <footer>
        &copy; 2023 Nova Consulting Group
    </footer>
</body>
</html>
'''

# Login page template
login_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Client Login - Nova Consulting Group</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #ecf0f1; margin: 0; padding: 0; }
        .login-container { width: 300px; padding: 40px; margin: auto; margin-top: 100px; background-color: white; box-shadow: 0px 0px 10px 0px #2C3E50; }
        h2 { text-align: center; color: #2C3E50; }
        input[type=text], input[type=password] { width: 100%; padding: 12px; margin: 5px 0 10px 0; border: none; background: #ecf0f1; }
        input[type=submit] { width: 100%; padding: 12px; background-color: #2C3E50; color: white; border: none; }
        input[type=submit]:hover { background-color: #34495E; }
        a { display: block; text-align: center; margin-top: 10px; color: #2C3E50; text-decoration: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Client Portal Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" value="Login">
        </form>
        <a href="/">Back to Home</a>
    </div>
</body>
</html>
'''

# Admin page template with congratulations message
admin_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard - Nova Consulting Group</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #FFFFFF; margin: 0; padding: 0; text-align: center; }
        h1 { margin-top: 50px; color: #27AE60; }
        p { color: #2C3E50; }
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully accessed the admin dashboard.</p>
</body>
</html>
'''

# About Us page template
about_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>About Us - Nova Consulting Group</title>
    <style>
        /* Styles similar to the main page for consistency */
    </style>
</head>
<body>
    <!-- Similar structure as the main page -->
    <header>
        <h1>About Nova Consulting Group</h1>
    </header>
    <div class="content">
        <p>
            Founded in 2005, Nova Consulting Group has been at the forefront of business innovation,
            providing unparalleled consulting services across various industries.
        </p>
    </div>
    <footer>
        &copy; 2023 Nova Consulting Group
    </footer>
</body>
</html>
'''

# Services page template
services_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Services - Nova Consulting Group</title>
    <style>
        /* Styles similar to the main page for consistency */
    </style>
</head>
<body>
    <!-- Similar structure as the main page -->
    <header>
        <h1>Our Services</h1>
    </header>
    <div class="content">
        <ul>
            <li>Business Strategy Development</li>
            <li>Market Analysis</li>
            <li>Operational Efficiency Optimization</li>
            <li>Technology Integration</li>
        </ul>
    </div>
    <footer>
        &copy; 2023 Nova Consulting Group
    </footer>
</body>
</html>
'''

# Contact page template
contact_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Contact Us - Nova Consulting Group</title>
    <style>
        /* Styles similar to the main page for consistency */
    </style>
</head>
<body>
    <!-- Similar structure as the main page -->
    <header>
        <h1>Contact Us</h1>
    </header>
    <div class="content">
        <p>
            Reach out to us for any inquiries or to schedule a consultation.
        </p>
        <p>Email: info@novaconsulting.com</p>
        <p>Phone: +1 (800) 123-4567</p>
    </div>
    <footer>
        &copy; 2023 Nova Consulting Group
    </footer>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(main_page)

@app.route('/about')
def about():
    return render_template_string(about_page)

@app.route('/services')
def services():
    return render_template_string(services_page)

@app.route('/contact')
def contact():
    return render_template_string(contact_page)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Authentication bypass vulnerability
        if username == 'admin' and password == 'admin':
            return redirect(url_for('admin'))
        else:
            # Vulnerability: Password is not checked properly
            if username == 'admin':
                return redirect(url_for('admin'))
            else:
                return render_template_string(login_page)
    else:
        return render_template_string(login_page)

@app.route('/admin')
def admin():
    return render_template_string(admin_page)

if __name__ == '__main__':
    app.run(debug=Fals)