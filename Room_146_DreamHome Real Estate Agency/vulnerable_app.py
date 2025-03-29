from flask import Flask, request
from flask import Markup

app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', 'Valued Customer')
    # HTML Injection vulnerability: 'name' is inserted into HTML without sanitization
    html_content = Markup(f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>DreamHome Real Estate Agency</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
            }}
            .header {{
                background-color: #004080;
                color: white;
                padding: 20px;
                text-align: center;
            }}
            .nav {{
                overflow: hidden;
                background-color: #333;
            }}
            .nav a {{
                float: left;
                display: block;
                color: #f2f2f2;
                text-align: center;
                padding: 14px 16px;
                text-decoration: none;
            }}
            .nav a:hover {{
                background-color: #ddd;
                color: black;
            }}
            .main {{
                padding: 20px;
            }}
            .property {{
                border: 1px solid #ccc;
                padding: 10px;
                margin: 10px 0;
            }}
            .footer {{
                background-color: #004080;
                color: white;
                text-align: center;
                padding: 10px;
                position: fixed;
                left: 0;
                bottom: 0;
                width: 100%;
            }}
            #congrats-message {{
                display: none;
                color: green;
                font-size: 20px;
            }}
        </style>
        <script>
            function showCongratulations() {{
                document.getElementById('congrats-message').style.display = 'block';
            }}
        </script>
    </head>
    <body>
        <div class="header">
            <h1>DreamHome Real Estate Agency</h1>
            <p>Your Dream Home Awaits</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/listings">Listings</a>
            <a href="/contact">Contact Us</a>
            <a href="/about">About Us</a>
        </div>
        <div class="main">
            <h2>Welcome, {name}!</h2>
            <p>We offer the best properties at the best prices.</p>
            <div class="property">
                <h3>Luxury Villa in Beverly Hills</h3>
                <p>5 beds | 6 baths | $5,000,000</p>
            </div>
            <div class="property">
                <h3>Modern Apartment in New York City</h3>
                <p>2 beds | 2 baths | $1,200,000</p>
            </div>
            <p id="congrats-message">Congratulations! You have found the hidden message.</p>
        </div>
        <div class="footer">
            &copy; 2023 DreamHome Real Estate Agency
        </div>
    </body>
    </html>
    ''')
    return html_content

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)