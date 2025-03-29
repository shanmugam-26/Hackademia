from flask import Flask, render_template, request, send_file, url_for
import os

app = Flask(__name__, template_folder=os.path.abspath('templates'))

# Create necessary directories and files
if not os.path.exists('templates'):
    os.makedirs('templates')

if not os.path.exists('static/css'):
    os.makedirs('static/css')

if not os.path.exists('articles'):
    os.makedirs('articles')

# Write CSS file
with open('static/css/style.css', 'w') as f:
    f.write("""
    @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
    body {
        font-family: 'Roboto', sans-serif;
        background-color: #ffffff;
        color: #333333;
        margin: 0;
        padding: 0;
    }
    header {
        background-color: #004080;
        color: #ffffff;
        padding: 20px 0;
    }
    header h1 {
        margin: 0;
        text-align: center;
        font-weight: 300;
    }
    nav {
        text-align: center;
        background-color: #003366;
        padding: 10px 0;
    }
    nav a {
        margin: 0 15px;
        color: #ffffff;
        text-decoration: none;
        font-weight: 400;
    }
    nav a:hover {
        text-decoration: underline;
    }
    .container {
        width: 80%;
        margin: 20px auto;
    }
    footer {
        background-color: #f2f2f2;
        color: #666666;
        text-align: center;
        padding: 10px 0;
        position: fixed;
        bottom: 0;
        width: 100%;
    }
    .article-title {
        font-weight: 700;
        margin-bottom: 10px;
    }
    .article-content {
        line-height: 1.6;
    }
    """)

# Write base template
with open('templates/base.html', 'w') as f:
    f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ title }} - Global News Network</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
</head>
<body>
    <header>
        <h1><a href="{{ url_for('index') }}" style="color:inherit; text-decoration:none;">Global News Network</a></h1>
    </header>
    <nav>
        <a href="{{ url_for('index') }}">Home</a>
        <a href="{{ url_for('about') }}">About</a>
        <a href="{{ url_for('contact') }}">Contact</a>
    </nav>
    <div class="container">
        {% block content %}{% endblock %}
    </div>
    <footer>
        <p>&copy; 2023 Global News Network</p>
    </footer>
</body>
</html>
""")

# Write index template
with open('templates/index.html', 'w') as f:
    f.write("""{% extends 'base.html' %}
{% block content %}
<h2>Latest News</h2>
<ul>
    <li><a href="{{ url_for('article', id='1') }}">Breaking News: Market Hits Record Highs</a></li>
    <li><a href="{{ url_for('article', id='2') }}">Sports Update: Local Team Wins Championship</a></li>
    <li><a href="{{ url_for('article', id='3') }}">Technology: New Smartphone Released</a></li>
</ul>
{% endblock %}
""")

# Write article template
with open('templates/article.html', 'w') as f:
    f.write("""{% extends 'base.html' %}
{% block content %}
<h2 class="article-title">{{ article_title }}</h2>
<div class="article-content">
    {{ content|safe }}
</div>
{% endblock %}
""")

# Write about and contact templates
with open('templates/about.html', 'w') as f:
    f.write("""{% extends 'base.html' %}
{% block content %}
<h2>About Us</h2>
<p>Global News Network is your trusted source for the latest news around the globe. Our team of dedicated journalists brings you in-depth coverage on a wide range of topics.</p>
{% endblock %}
""")

with open('templates/contact.html', 'w') as f:
    f.write("""{% extends 'base.html' %}
{% block content %}
<h2>Contact Us</h2>
<p>Have questions or comments? Reach out to us through the following channels:</p>
<ul>
    <li>Email: <a href="mailto:contact@gnn.com">contact@gnn.com</a></li>
    <li>Phone: +1 234 567 8900</li>
    <li>Address: 123 News Lane, Media City, NY</li>
</ul>
{% endblock %}
""")

# Write articles
articles_content = {
    '1.html': "<p>In an unprecedented turn, the stock market soared to new heights today, with the S&P 500 closing at a record high. Analysts attribute this surge to positive earnings reports and optimistic economic forecasts.</p>",
    '2.html': "<p>The hometown heroes clinched the championship in a thrilling match that kept fans on the edge of their seats. This marks their third consecutive win, solidifying their legacy in sports history.</p>",
    '3.html': "<p>The latest smartphone model has been released, featuring cutting-edge technology and innovative design. Early reviews praise its performance and sleek aesthetics.</p>"
}

for filename, content in articles_content.items():
    with open(f'articles/{filename}', 'w') as f:
        f.write(content)

# Write secret file
if not os.path.exists('secret'):
    os.makedirs('secret')
with open('secret/congrats.txt', 'w') as f:
    f.write("Congratulations! You've found the hidden message. Your skills are impressive!")

@app.route('/')
def index():
    return render_template('index.html', title='Home')

@app.route('/article')
def article():
    article_id = request.args.get('id', '1')
    try:
        # Insecure path handling - directory traversal vulnerability
        article_path = os.path.join('articles', article_id + '.html')
        with open(article_path, 'r') as f:
            content = f.read()
        titles = {
            '1': 'Breaking News: Market Hits Record Highs',
            '2': 'Sports Update: Local Team Wins Championship',
            '3': 'Technology: New Smartphone Released'
        }
        article_title = titles.get(article_id, 'News Article')
        return render_template('article.html', title=article_title, article_title=article_title, content=content)
    except Exception as e:
        return render_template('article.html', title='Article Not Found', article_title='Article Not Found', content='<p>Sorry, the article you are looking for does not exist.</p>')

@app.route('/about')
def about():
    return render_template('about.html', title='About Us')

@app.route('/contact')
def contact():
    return render_template('contact.html', title='Contact Us')

if __name__ == "__main__":
    app.run(debug=True)