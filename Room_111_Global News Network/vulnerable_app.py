from flask import Flask, render_template_string, request, redirect
app = Flask(__name__)

@app.route('/')
def index():
    articles = [
        {'title': 'Breaking News: AI Advances in 2023', 'content': 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin nec fermentum lorem.'},
        {'title': 'Economy Update: Markets on the Rise', 'content': 'Vivamus vulputate, mauris nec venenatis ultrices, arcu sem tincidunt est, vitae vehicula erat quam eget massa.'},
        {'title': 'Health: New Vaccine Developed', 'content': 'Suspendisse potenti. Fusce non urna vel dolor placerat convallis.'}
    ]
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Global News Network</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
        }
        .header {
            background-color: #004080;
            color: white;
            padding: 20px;
            text-align: center;
        }
        .article {
            background-color: white;
            margin: 20px;
            padding: 20px;
            border-radius: 10px;
        }
        .article h2 {
            color: #004080;
        }
        .article a {
            color: #004080;
            text-decoration: none;
            font-weight: bold;
        }
        .footer {
            background-color: #004080;
            color: white;
            padding: 10px;
            text-align: center;
            position: fixed;
            left:0;
            bottom:0;
            width:100%;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Global News Network</h1>
        <p>Your trusted source for the latest news.</p>
    </div>
    <div class="content">
        {% for article in articles %}
        <div class="article">
            <h2>{{ article.title }}</h2>
            <p>{{ article.content }}</p>
            <a href="/redirect?url=/articles/{{ loop.index }}">Read more</a>
        </div>
        {% endfor %}
    </div>
    <div class="footer">
        &copy; 2023 Global News Network
    </div>
</body>
</html>
''', articles=articles)

@app.route('/redirect')
def vuln_redirect():
    url = request.args.get('url')
    if url:
        return redirect(url)
    else:
        return redirect('/')

@app.route('/articles/<int:article_id>')
def article_detail(article_id):
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Article Details</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 40px;
        }
        h1 {
            color: #004080;
        }
        a {
            color: #004080;
            text-decoration: none;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>Article {{ article_id }}</h1>
    <p>Detailed content for article {{ article_id }} goes here. Stay tuned for more updates.</p>
    <a href="/">Back to Home</a>
</body>
</html>
''', article_id=article_id)

@app.route('/congrats')
def congrats():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Congratulations!</title>
    <style>
        body {
            background-color: #004080;
            color: white;
            font-family: Arial, sans-serif;
            text-align: center;
            padding-top: 100px;
        }
        h1 {
            font-size: 48px;
        }
        p {
            font-size: 24px;
        }
        a {
            color: #ffcc00;
            text-decoration: none;
            font-weight: bold;
            font-size: 20px;
        }
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the vulnerability.</p>
    <a href="/">Return to Home</a>
</body>
</html>
''')

if __name__ == '__main__':
    app.run(debug=True)