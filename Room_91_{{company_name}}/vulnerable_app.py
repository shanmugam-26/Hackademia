from flask import Flask, render_template_string, request, redirect, url_for
import requests
import datetime

app = Flask(__name__)

company_name = "TechNova Solutions"

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{company_name}}</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
            .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
            .nav { overflow: hidden; background-color: #333; }
            .nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                     padding: 14px 16px; text-decoration: none; }
            .nav a:hover { background-color: #ddd; color: black; }
            .container { padding: 20px; }
            .feature { margin-top: 20px; }
            input[type="text"] { width: 70%; padding: 10px; margin-right: 10px; }
            input[type="submit"] { padding: 10px 20px; }
            .footer { background-color: #333; color: white; text-align: center; padding: 10px; position: fixed;
                      left: 0; bottom: 0; width: 100%; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome to {{company_name}}</h1>
            <p>Innovating the future, one solution at a time.</p>
        </div>
        <div class="nav">
            <a href="{{url_for('index')}}">Home</a>
            <a href="{{url_for('about')}}">About Us</a>
            <a href="{{url_for('services')}}">Services</a>
            <a href="{{url_for('contact')}}">Contact</a>
        </div>
        <div class="container">
            <h2>Latest News</h2>
            <p>Stay tuned for our upcoming product launch!</p>
            <div class="feature">
                <h2>Partner Website Lookup</h2>
                <form action="{{url_for('lookup')}}" method="post">
                    <input type="text" name="domain" placeholder="Enter partner domain" required />
                    <input type="submit" value="Lookup" />
                </form>
            </div>
        </div>
        <div class="footer">
            &copy; {{year}} {{company_name}}. All rights reserved.
        </div>
    </body>
    </html>
    ''', company_name=company_name, year=datetime.datetime.now().year)

@app.route('/about')
def about():
    return render_template_string('''
    <h1>About Us</h1>
    <p>{{company_name}} is a leading provider of innovative tech solutions.</p>
    <a href="{{url_for('index')}}">Back to Home</a>
    ''', company_name=company_name)

@app.route('/services')
def services():
    return render_template_string('''
    <h1>Our Services</h1>
    <ul>
        <li>Software Development</li>
        <li>Cloud Services</li>
        <li>AI & Machine Learning</li>
    </ul>
    <a href="{{url_for('index')}}">Back to Home</a>
    ''')

@app.route('/contact')
def contact():
    return render_template_string('''
    <h1>Contact Us</h1>
    <p>Email: info@technova.com</p>
    <a href="{{url_for('index')}}">Back to Home</a>
    ''')

@app.route('/lookup', methods=['POST'])
def lookup():
    domain = request.form.get('domain')
    if not domain.startswith('http://') and not domain.startswith('https://'):
        domain = 'http://' + domain

    try:
        resp = requests.get(domain, timeout=5)
        status_code = resp.status_code
        content = resp.text[:500]

        # Hidden endpoint detection
        if 'Congratulations' in content:
            return render_template_string('''
            <h1>Congratulations!</h1>
            <p>You have discovered the hidden message.</p>
            <a href="{{url_for('index')}}">Back to Home</a>
            ''')

        return render_template_string('''
        <h1>Domain Lookup Result</h1>
        <p>Status Code: {{status_code}}</p>
        <p>Content Preview:</p>
        <pre>{{content}}</pre>
        <a href="{{url_for('index')}}">Back to Home</a>
        ''', status_code=status_code, content=content)
    except Exception as e:
        return render_template_string('''
        <h1>Error Occurred</h1>
        <p>{{error}}</p>
        <a href="{{url_for('index')}}">Back to Home</a>
        ''', error=str(e))

# Hidden internal endpoint
@app.route('/internal/secret')
def secret():
    return "Congratulations! You have found the secret internal page."

if __name__ == '__main__':
    app.run(debug=True)