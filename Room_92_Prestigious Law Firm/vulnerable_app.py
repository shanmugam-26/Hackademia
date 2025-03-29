from flask import Flask, render_template_string

app = Flask(__name__)

# Security Misconfiguration: DEBUG mode is set to True in production
app.config['DEBUG'] = True

template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Prestigious Law Firm</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f0f0; margin: 0; }
        .header { background-color: #00274c; color: white; padding: 20px; text-align: center; }
        .nav { background-color: #014f86; overflow: hidden; }
        .nav a { float: left; display: block; color: white; text-align: center; padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #01325a; }
        .content { padding: 20px; }
        .footer { background-color: #00274c; color: white; text-align: center; padding: 10px; position: fixed; width: 100%; bottom: 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Smith & Associates Law Firm</h1>
        <p>Excellence in Legal Services Since 1990</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/services">Services</a>
        <a href="/contact">Contact</a>
    </div>
    <div class="content">
        <h2>Welcome to Smith & Associates</h2>
        <p>We provide comprehensive legal solutions tailored to your needs.</p>
    </div>
    <div class="footer">
        &copy; {{ year }} Smith & Associates Law Firm. All rights reserved.
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    from datetime import datetime
    return render_template_string(template, year=datetime.now().year)

# Security Misconfiguration: Exposed configuration file route
@app.route('/config')
def config():
    with open('config.py', 'r') as f:
        return '<pre>' + f.read() + '</pre>'

if __name__ == '__main__':
    app.run()