from flask import Flask, render_template_string, request, redirect, url_for, flash
import os

app = Flask(__name__)
app.secret_key = 'ThisIsASecretKey'  # Hardcoded secret key (misconfiguration)

# Security misconfiguration: DEBUG is set to True in production
app.debug = True

# Security misconfiguration: Exposing the config
@app.route('/config')
def config():
    config_info = ""
    for k in app.config:
        config_info += f"{k}: {app.config[k]}<br>"
    return config_info

# Home page
@app.route('/')
def index():
    return render_template_string('''
    <html>
    <head>
        <title>Global Health Initiative</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
            .header {background-color: #4CAF50; color: white; padding: 20px; text-align: center;}
            .content {padding: 20px;}
            .footer {background-color: #ddd; color: #333; padding: 10px; text-align: center;}
            a {color: #4CAF50;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Global Health Initiative</h1>
        </div>
        <div class="content">
            <h2>Our Mission</h2>
            <p>At Global Health Initiative, we strive to improve healthcare access worldwide.</p>
            <h2>Get Involved</h2>
            <p><a href="/donate">Donate</a> | <a href="/volunteer">Volunteer</a> | <a href="/contact">Contact Us</a></p>
        </div>
        <div class="footer">
            &copy; 2023 Global Health Initiative
        </div>
    </body>
    </html>
    ''')

@app.route('/donate')
def donate():
    return render_template_string('''
    <html>
    <head>
        <title>Donate - Global Health Initiative</title>
    </head>
    <body>
        <h1>Donate</h1>
        <p>Your contributions help us save lives.</p>
        <form action="/thank_you" method="post">
            <label>Name: <input type="text" name="name"></label><br>
            <label>Amount: <input type="number" name="amount"></label><br>
            <button type="submit">Donate</button>
        </form>
    </body>
    </html>
    ''')

@app.route('/thank_you', methods=['POST'])
def thank_you():
    name = request.form.get('name', 'Donor')
    amount = request.form.get('amount', '0')
    return render_template_string(f'''
    <html>
    <head>
        <title>Thank You - Global Health Initiative</title>
    </head>
    <body>
        <h1>Thank You, {name}!</h1>
        <p>We appreciate your generous donation of ${amount}.</p>
    </body>
    </html>
    ''')

@app.route('/admin')
def admin():
    return render_template_string('''
    <html>
    <head>
        <title>Admin Panel</title>
    </head>
    <body>
        <h1>Admin Panel</h1>
        <p>Welcome, Admin!</p>
    </body>
    </html>
    ''')

# Security misconfiguration: Exposed admin panel

# Hidden congratulations message
@app.route('/congratulations')
def congratulations():
    return "Congratulations! You have found and exploited the security misconfiguration vulnerability."

if __name__ == '__main__':
    # Security misconfiguration: Running on all interfaces
    app.run(host='0.0.0.0', port=5000)