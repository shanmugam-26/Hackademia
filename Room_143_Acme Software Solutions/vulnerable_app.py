from flask import Flask, render_template_string

app = Flask(__name__)

home_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Acme Software Solutions</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f0f2f5; margin: 0; padding: 0;}
        .header {background-color: #283e4a; color: white; padding: 20px; text-align: center;}
        .navbar {overflow: hidden; background-color: #333;}
        .navbar a {float: left; display: block; color: #f2f2f2; text-align: center;
                   padding: 14px 16px; text-decoration: none;}
        .navbar a:hover {background-color: #ddd; color: black;}
        .content {padding: 20px;}
        .footer {background-color: #283e4a; color: white; padding: 10px; text-align: center;}
    </style>
</head>
<body>
    <div class="header">
        <h1>Acme Software Solutions</h1>
        <p>Innovating the future, one line of code at a time.</p>
    </div>
    <div class="navbar">
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/careers">Careers</a>
    </div>
    <div class="content">
        <h2>Welcome to Acme Software Solutions</h2>
        <p>At Acme, we specialize in delivering top-notch software solutions tailored to your business needs.</p>
        <p>Our team of experts is dedicated to pushing the boundaries of technology to deliver innovative solutions.</p>
    </div>
    <div class="footer">
        <p>Contact us at info@acmesoftwaresolutions.com | &copy; 2023 Acme Software Solutions</p>
    </div>
</body>
</html>
'''

about_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>About Us - Acme Software Solutions</title>
</head>
<body>
    <h1>About Us</h1>
    <p>Acme Software Solutions was founded in 2000 with the mission to create world-class software applications.</p>
    <p>We pride ourselves on our commitment to excellence and customer satisfaction.</p>
</body>
</html>
'''

careers_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Careers - Acme Software Solutions</title>
</head>
<body>
    <h1>Careers</h1>
    <p>Join our dynamic team and be a part of the future of technology.</p>
    <p>Send your resume to careers@acmesoftwaresolutions.com.</p>
</body>
</html>
'''

app = Flask(__name__)

# Secret message for users who exploit the vulnerability
secret_message = "Congratulations! You've successfully exploited the security misconfiguration vulnerability."

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/about')
def about():
    return render_template_string(about_page)

@app.route('/careers')
def careers():
    return render_template_string(careers_page)

# Intentionally vulnerable route
@app.route('/profile')
def profile():
    # Simulate a server error to expose debug information
    return 1 / 0  # This will cause a ZeroDivisionError

if __name__ == '__main__':
    # Misconfigured to have debug mode enabled in production
    app.run(debug=True)