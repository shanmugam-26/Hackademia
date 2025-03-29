from flask import Flask, request
from flask import render_template_string

app = Flask(__name__)

# The main page route
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Elegance Fashion House</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            .header { background-color: #fff8f0; padding: 20px; text-align: center; }
            .header h1 { margin: 0; font-size: 3em; color: #333; }
            .nav { background-color: #333; padding: 10px; }
            .nav a { color: white; margin: 0 15px; text-decoration: none; }
            .banner { background-image: url('https://example.com/banner.jpg'); background-size: cover; background-position: center; height: 400px; color: white; display: flex; align-items: center; justify-content: center; }
            .banner h2 { font-size: 4em; background-color: rgba(0, 0, 0, 0.5); padding: 20px; }
            .content { padding: 20px; }
            .footer { background-color: #333; color: white; text-align: center; padding: 10px; }
            .search-box { margin: 20px 0; }
            .search-box input { padding: 10px; width: 300px; }
            .search-box button { padding: 10px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Elegance Fashion House</h1>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/collections">Collections</a>
            <a href="/about">About Us</a>
            <a href="/contact">Contact</a>
        </div>
        <div class="banner">
            <h2>Where Style Meets Elegance</h2>
        </div>
        <div class="content">
            <div class="search-box">
                <form action="/search" method="get">
                    <input type="text" name="query" placeholder="Search our collection..." />
                    <button type="submit">Search</button>
                </form>
            </div>
            <h3>Welcome to Elegance Fashion House</h3>
            <p>Discover our latest trends in fashion and accessories. We bring you the finest selection from around the world to complement your style.</p>
        </div>
        <div class="footer">
            <p>&copy; 2023 Elegance Fashion House. All rights reserved.</p>
        </div>
    </body>
    </html>
    '''

# The search route with the HTML injection vulnerability
@app.route('/search')
def search():
    query = request.args.get('query', '')
    # Vulnerable to HTML Injection
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Results - Elegance Fashion House</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            .header { background-color: #fff8f0; padding: 20px; text-align: center; }
            .header h1 { margin: 0; font-size: 3em; color: #333; }
            .nav { background-color: #333; padding: 10px; }
            .nav a { color: white; margin: 0 15px; text-decoration: none; }
            .content { padding: 20px; }
            .footer { background-color: #333; color: white; text-align: center; padding: 10px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Elegance Fashion House</h1>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/collections">Collections</a>
            <a href="/about">About Us</a>
            <a href="/contact">Contact</a>
        </div>
        <div class="content">
            <h3>Search Results for: {{ query|safe }}</h3>
            <p>Sorry, no results found for your search.</p>
        </div>
        <div class="footer">
            <p>&copy; 2023 Elegance Fashion House. All rights reserved.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, query=query)

# Success page after exploiting the vulnerability
@app.route('/congratulations')
def congratulations():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Congratulations!</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #e0ffe0; text-align: center; padding-top: 50px; }
            h1 { color: #008000; font-size: 3em; }
            p { font-size: 1.5em; }
        </style>
    </head>
    <body>
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the HTML Injection vulnerability.</p>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)