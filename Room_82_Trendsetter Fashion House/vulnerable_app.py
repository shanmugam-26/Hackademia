from flask import Flask, request
from markupsafe import escape
app = Flask(__name__)

html_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Trendsetter Fashion House</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f4;
        }}
        header {{
            background-color: #fff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            position: fixed;
            width: 100%;
            top: 0;
            z-index: 1000;
        }}
        .logo {{
            font-size: 24px;
            font-weight: bold;
            padding: 15px;
            color: #333;
            text-decoration: none;
            display: inline-block;
        }}
        nav {{
            display: inline-block;
            float: right;
            margin-top: 15px;
        }}
        nav a {{
            margin: 0 15px;
            color: #333;
            text-decoration: none;
            font-size: 16px;
        }}
        main {{
            margin-top: 80px;
            padding: 20px;
        }}
        footer {{
            background-color: #333;
            color: #fff;
            text-align: center;
            padding: 10px;
            position: fixed;
            width: 100%;
            bottom: 0;
        }}
        .banner {{
            width: 100%;
            height: 400px;
            background-image: url('https://via.placeholder.com/1920x400');
            background-size: cover;
            background-position: center;
            position: relative;
        }}
        .banner-text {{
            position: absolute;
            bottom: 40px;
            left: 40px;
            color: #fff;
            font-size: 48px;
            font-weight: bold;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }}
        .collection {{
            display: flex;
            flex-wrap: wrap;
            justify-content: space-around;
        }}
        .item {{
            width: 30%;
            margin: 15px 0;
            background-color: #fff;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            padding: 10px;
        }}
        .item img {{
            max-width: 100%;
            height: auto;
        }}
        .item h3 {{
            margin: 10px 0;
        }}
        .item p {{
            color: #777;
        }}
        .feedback-form {{
            margin-top: 40px;
        }}
        .feedback-form input[type="text"] {{
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
        }}
        .feedback-form input[type="submit"] {{
            padding: 10px 20px;
            background-color: #333;
            color: #fff;
            border: none;
        }}
        .user-feedback {{
            background-color: #fff;
            padding: 20px;
            margin-top: 20px;
        }}
        .congrats {{
            display: none;
            padding: 20px;
            background-color: #dff0d8;
            color: #3c763d;
            margin-top: 20px;
            text-align: center;
            font-size: 18px;
        }}
    </style>
</head>
<body>
    <header>
        <a href="#" class="logo">Trendsetter</a>
        <nav>
            <a href="#">Home</a>
            <a href="#">Collection</a>
            <a href="#">About</a>
            <a href="#">Contact</a>
        </nav>
    </header>
    <main>
        <div class="banner">
            <div class="banner-text">Fall Collection 2023</div>
        </div>
        <div class="collection">
            <div class="item">
                <img src="https://via.placeholder.com/300x400" alt="Item 1">
                <h3>Autumn Ensemble</h3>
                <p>Embrace the hues of fall.</p>
            </div>
            <div class="item">
                <img src="https://via.placeholder.com/300x400" alt="Item 2">
                <h3>Winter Warmth</h3>
                <p>Stay cozy and stylish.</p>
            </div>
            <div class="item">
                <img src="https://via.placeholder.com/300x400" alt="Item 3">
                <h3>Spring Blossom</h3>
                <p>Fresh looks for a new season.</p>
            </div>
        </div>
        <div class="feedback-form">
            <h2>We Value Your Feedback</h2>
            <form method="get" action="/">
                <input type="text" name="feedback" placeholder="Enter your feedback here">
                <input type="submit" value="Submit">
            </form>
        </div>
        <div class="user-feedback">
            <h3>Your Feedback:</h3>
            <p>{{ feedback | safe }}</p>
        </div>
        <div class="congrats" id="congratsMessage">
            Congratulations! You've successfully exploited the vulnerability.
        </div>
    </main>
    <footer>
        &copy; 2023 Trendsetter Fashion House
    </footer>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    feedback = request.args.get('feedback', '')
    response = html_page.format(feedback=feedback)
    return response

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)