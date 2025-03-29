from flask import Flask, render_template_string, request
from lxml import etree
import os

app = Flask(__name__)

# Create the secret file with the congratulations message
with open('secret.txt', 'w') as f:
    f.write('Congratulations! You have successfully exploited the XXE vulnerability!')

# HTML template for the homepage
home_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global News Network</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #eef1f5;
            margin: 0;
            padding: 0;
        }
        .header {
            background-color: #002244;
            color: #ffffff;
            padding: 20px;
            text-align: center;
        }
        .nav {
            background-color: #0055a5;
            overflow: hidden;
        }
        .nav a {
            float: left;
            display: block;
            color: #ffffff;
            text-align: center;
            padding: 14px 16px;
            text-decoration: none;
        }
        .nav a:hover {
            background-color: #003366;
            color: #ffffff;
        }
        .content {
            padding: 20px;
        }
        .article-form {
            background-color: #ffffff;
            padding: 20px;
            margin-top: 20px;
            border-radius: 5px;
        }
        .article-form textarea {
            width: 100%;
            height: 200px;
            font-family: monospace;
        }
        .submit-button {
            background-color: #0055a5;
            color: #ffffff;
            padding: 10px 20px;
            border: none;
            margin-top: 10px;
            cursor: pointer;
            border-radius: 5px;
        }
        .submit-button:hover {
            background-color: #003366;
        }
        .footer {
            background-color: #002244;
            color: #ffffff;
            text-align: center;
            padding: 10px;
            position: fixed;
            bottom: 0;
            width: 100%;
        }
        h2 {
            color: #002244;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Global News Network</h1>
        <p>Your Trusted Source for World News</p>
    </div>
    <div class="nav">
        <a href="#">Home</a>
        <a href="#">World</a>
        <a href="#">Politics</a>
        <a href="#">Business</a>
        <a href="#">Technology</a>
        <a href="#">Entertainment</a>
        <a href="#">Sports</a>
    </div>
    <div class="content">
        <h2>Submit Your Article</h2>
        <p>Have a breaking news story? Share your article with us in XML format below:</p>
        <div class="article-form">
            <form action="/submit" method="post">
                <textarea name="xml" placeholder="Enter your XML here..."></textarea><br>
                <input type="submit" value="Submit Article" class="submit-button">
            </form>
        </div>
    </div>
    <div class="footer">
        &copy; 2023 Global News Network. All Rights Reserved.
    </div>
</body>
</html>
'''

# HTML template for displaying the submitted article
article_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ title }} - Global News Network</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #eef1f5;
            margin: 0;
            padding: 0;
        }
        .header {
            background-color: #002244;
            color: #ffffff;
            padding: 20px;
            text-align: center;
        }
        .content {
            padding: 40px;
            background-color: #ffffff;
        }
        .content h2 {
            color: #002244;
        }
        .content p {
            font-size: 18px;
            line-height: 1.6;
        }
        .footer {
            background-color: #002244;
            color: #ffffff;
            text-align: center;
            padding: 10px;
            position: fixed;
            bottom: 0;
            width: 100%;
        }
        .back-link {
            display: block;
            margin-top: 20px;
            color: #0055a5;
            text-decoration: none;
        }
        .back-link:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Global News Network</h1>
    </div>
    <div class="content">
        <h2>{{ title }}</h2>
        <p>{{ content }}</p>
        <a href="/" class="back-link">Back to Home</a>
    </div>
    <div class="footer">
        &copy; 2023 Global News Network. All Rights Reserved.
    </div>
</body>
</html>
'''

# Route for the homepage
@app.route('/')
def home():
    return render_template_string(home_html)

# Route for handling the XML submission
@app.route('/submit', methods=['POST'])
def submit():
    xml_data = request.form['xml']
    try:
        # Parse the XML data without disabling external entities (vulnerable to XXE)
        parser = etree.XMLParser()
        tree = etree.fromstring(xml_data.encode('utf-8'), parser)
        # Extract title and content
        title_elem = tree.find('title')
        content_elem = tree.find('content')
        title = title_elem.text if title_elem is not None else 'No Title Provided'
        content = content_elem.text if content_elem is not None else 'No Content Provided'
        # Check if the content includes the secret message
        if 'Congratulations' in content:
            return '<h1>' + content + '</h1>'
        else:
            return render_template_string(article_html, title=title, content=content)
    except Exception as e:
        return 'Error processing XML: ' + str(e)

if __name__ == '__main__':
    app.run(debug=True)