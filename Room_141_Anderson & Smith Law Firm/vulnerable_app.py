from flask import Flask, render_template_string, request, redirect, url_for
import random
import string

app = Flask(__name__)

# Simulate a database of articles
articles = [
    {"id": 1, "title": "Corporate Law Insights", "content": "An in-depth analysis of corporate regulations."},
    {"id": 2, "title": "Intellectual Property Rights", "content": "Protecting your innovations in the digital age."},
    {"id": 3, "title": "International Trade Agreements", "content": "Navigating the complexities of global commerce."},
]

home_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Anderson & Smith Law Firm</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #ffffff; margin: 0; padding: 0; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
        .nav { overflow: hidden; background-color: #34495e; }
        .nav a { float: left; display: block; color: #ecf0f1; text-align: center; padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #1abc9c; color: white; }
        .banner { background-image: url('https://example.com/banner.jpg'); background-size: cover; padding: 60px; color: white; text-align: center; }
        .content { padding: 20px; }
        .footer { background-color: #2c3e50; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
        .article { border-bottom: 1px solid #bdc3c7; padding-bottom: 10px; margin-bottom: 10px; }
        .search-bar { margin: 20px 0; }
        input[type="text"] { width: 80%; padding: 10px; }
        input[type="submit"] { padding: 10px 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Anderson & Smith Law Firm</h1>
        <p>Excellence. Integrity. Justice.</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/team">Our Team</a>
        <a href="/practice">Practice Areas</a>
        <a href="/contact">Contact Us</a>
    </div>
    <div class="banner">
        <h2>Leading the Way in Legal Innovation</h2>
        <p>Providing clients with skilled legal advice in a timely and efficient manner.</p>
    </div>
    <div class="content">
        <div class="search-bar">
            <form action="/search" method="GET">
                <input type="text" name="query" placeholder="Search articles, cases, and more...">
                <input type="submit" value="Search">
            </form>
        </div>
        <h2>Latest Articles</h2>
        {% for article in articles %}
        <div class="article">
            <h3><a href="/article/{{ article.id }}">{{ article.title }}</a></h3>
            <p>{{ article.content[:100] }}...</p>
        </div>
        {% endfor %}
    </div>
    <div class="footer">
        &copy; 2023 Anderson & Smith Law Firm | <a href="/privacy" style="color: #ecf0f1;">Privacy Policy</a>
    </div>
</body>
</html>
"""

article_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ article.title }} - Anderson & Smith Law Firm</title>
    <!-- Reusing styles from home page for consistency -->
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #ffffff; margin: 0; padding: 0; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
        .nav { overflow: hidden; background-color: #34495e; }
        .nav a { float: left; display: block; color: #ecf0f1; text-align: center; padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #1abc9c; color: white; }
        .content { padding: 20px; }
        .footer { background-color: #2c3e50; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Anderson & Smith Law Firm</h1>
        <p>Excellence. Integrity. Justice.</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/team">Our Team</a>
        <a href="/practice">Practice Areas</a>
        <a href="/contact">Contact Us</a>
    </div>
    <div class="content">
        <h2>{{ article.title }}</h2>
        <p>{{ article.content }}</p>
        <a href="/">&#8592; Back to Home</a>
    </div>
    <div class="footer">
        &copy; 2023 Anderson & Smith Law Firm | <a href="/privacy" style="color: #ecf0f1;">Privacy Policy</a>
    </div>
</body>
</html>
"""

search_results_page = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Search Results for "{{ query | safe}}" - Anderson & Smith Law Firm</title>
    <!-- Reusing styles from home page for consistency -->
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #ffffff; margin: 0; padding: 0; }
        .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
        .nav { overflow: hidden; background-color: #34495e; }
        .nav a { float: left; display: block; color: #ecf0f1; text-align: center; padding: 14px 16px; text-decoration: none; }
        .nav a:hover { background-color: #1abc9c; color: white; }
        .content { padding: 20px; }
        .footer { background-color: #2c3e50; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
        .highlight { background-color: yellow; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Anderson & Smith Law Firm</h1>
        <p>Excellence. Integrity. Justice.</p>
    </div>
    <div class="nav">
        <a href="/">Home</a>
        <a href="/team">Our Team</a>
        <a href="/practice">Practice Areas</a>
        <a href="/contact">Contact Us</a>
    </div>
    <div class="content">
        <h2>Search Results for "{{ query }}"</h2>
        {% if results %}
            {% for result in results %}
                <div class="article">
                    <h3><a href="/article/{{ result.id }}">{{ result.title }}</a></h3>
                    <p>{{ result.content[:150] }}...</p>
                </div>
            {% endfor %}
        {% else %}
            <p>Your search did not match any documents.</p>
        {% endif %}
        <a href="/">&#8592; Back to Home</a>
    </div>
    <div class="footer">
        &copy; 2023 Anderson & Smith Law Firm | <a href="/privacy" style="color: #ecf0f1;">Privacy Policy</a>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(home_page, articles=articles)

@app.route('/article/<int:article_id>')
def article(article_id):
    article = next((a for a in articles if a["id"] == article_id), None)
    if article:
        return render_template_string(article_page, article=article)
    else:
        return redirect(url_for('home'))

@app.route('/search')
def search():
    query = request.args.get('query', '')
    # Intentionally vulnerable to XSS
    # In a real application, you should sanitize the input to prevent XSS
    results = [a for a in articles if query.lower() in a["title"].lower() or query.lower() in a["content"].lower()]
    return render_template_string(search_results_page, query=query, results=results)

@app.route('/team')
def team():
    # Dummy content for additional pages
    return redirect(url_for('home'))

@app.route('/practice')
def practice():
    # Dummy content for additional pages
    return redirect(url_for('home'))

@app.route('/contact')
def contact():
    # Dummy content for additional pages
    return redirect(url_for('home'))

@app.route('/privacy')
def privacy():
    # Dummy content for additional pages
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=False)