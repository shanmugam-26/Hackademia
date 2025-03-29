from flask import Flask, request, render_template_string

app = Flask(__name__)

home_page_content = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>International Daily Times</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 0; }}
        header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
        nav {{ background-color: #34495e; overflow: hidden; }}
        nav a {{ float: left; display: block; color: white; text-align: center; padding: 14px 16px; text-decoration: none; }}
        nav a:hover {{ background-color: #2c3e50; }}
        .content {{ padding: 20px; }}
        footer {{ background-color: #2c3e50; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }}
    </style>
</head>
<body>
    <header>
        <h1>International Daily Times</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/world">World</a>
        <a href="/technology">Technology</a>
        <a href="/culture">Culture</a>
        <a href="/contact">Contact</a>
    </nav>
    <div class="content">
        <h2>Global Summit on Climate Change Concludes with Historic Agreement</h2>
        <p>Leaders from around the world have come together to sign a landmark agreement...</p>
        <p>We value your voice. Share your thoughts below:</p>
        <form action="/feedback" method="post">
            <input type="text" name="feedback" placeholder="Your feedback" style="width: 300px;">
            <input type="submit" value="Submit">
        </form>
    </div>
    <footer>
        &copy; 2023 International Daily Times
    </footer>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def home():
    return home_page_content

@app.route('/feedback', methods=['POST'])
def feedback():
    feedback = request.form.get('feedback', '')
    response_content = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Feedback Received - International Daily Times</title>
        <style>
            body {{ font-family: Arial, sans-serif; padding: 20px; }}
            .message {{ background-color: #ecf0f1; padding: 20px; border-radius: 5px; }}
            a {{ text-decoration: none; color: #2980b9; }}
        </style>
    </head>
    <body>
        <h1>Thank You for Your Feedback</h1>
        <div class="message">
            <p>Your feedback:</p>
            <p>{}</p>
        </div>
        <p><a href="/">Return to Homepage</a></p>
    </body>
    </html>
    '''.format(feedback)
    return response_content

@app.errorhandler(500)
def internal_error(error):
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Congratulations!</title>
        <style>
            body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
            h1 {{ color: #27ae60; }}
        </style>
    </head>
    <body>
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the HTML Injection vulnerability.</p>
    </body>
    </html>
    ''', 200

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)