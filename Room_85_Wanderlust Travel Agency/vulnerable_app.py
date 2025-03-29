from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Wanderlust Travel Agency</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f8ff; margin: 0; }
        header { background-color: #ff7f50; color: white; padding: 20px; text-align: center; }
        nav { display: flex; justify-content: center; background-color: #ff6347; }
        nav a { color: white; padding: 14px 20px; text-decoration: none; text-align: center; }
        nav a:hover { background-color: #ffa07a; }
        .hero { background-image: url('https://example.com/hero.jpg'); height: 400px; background-size: cover; position: relative; }
        .hero-text { text-align: center; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); color: white; }
        .container { padding: 20px; }
        footer { background-color: #ff7f50; color: white; padding: 10px; text-align: center; position: fixed; width: 100%; bottom: 0; }
        .search-box { margin-top: 20px; text-align: center; }
        .search-box input[type="text"] { width: 300px; padding: 10px; }
        .search-box input[type="submit"] { padding: 10px 20px; }
    </style>
</head>
<body>
    <header>
        <h1>Wanderlust Travel Agency</h1>
        <p>Your Gateway to Exotic Destinations</p>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/destinations">Destinations</a>
        <a href="/about">About Us</a>
        <a href="/contact">Contact</a>
    </nav>
    <div class="hero">
        <div class="hero-text">
            <h2>Discover Your Next Adventure</h2>
            <p>Exclusive deals available now!</p>
        </div>
    </div>
    <div class="container">
        <h2>Search for Your Dream Destination</h2>
        <div class="search-box">
            <form action="/search" method="get">
                <input type="text" name="query" placeholder="Enter destination">
                <input type="submit" value="Search">
            </form>
        </div>
    </div>
    <footer>
        <p>&copy; 2023 Wanderlust Travel Agency</p>
    </footer>
</body>
</html>
''')

@app.route('/search')
def search():
    query = request.args.get('query', '')
    # Vulnerable to XSS
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Search Results - {{ query }}</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #ffffff; margin: 0; }
        header { background-color: #ff7f50; color: white; padding: 20px; text-align: center; }
        .container { padding: 20px; }
        footer { background-color: #ff7f50; color: white; padding: 10px; text-align: center; position: fixed; width: 100%; bottom: 0; }
    </style>
</head>
<body>
    <header>
        <h1>Search Results</h1>
    </header>
    <div class="container">
        <h2>Your search for "{{ query | safe }}" returned no results.</h2>
        <p>Please try a different destination.</p>
    </div>
    <footer>
        <p>&copy; 2023 Wanderlust Travel Agency</p>
    </footer>
</body>
</html>
''', query=query)

@app.route('/congratulations')
def congratulations():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Congratulations!</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #dff0d8; margin: 0; }
        .message { text-align: center; padding: 100px; }
        h1 { color: #3c763d; }
        p { color: #3c763d; font-size: 18px; }
    </style>
</head>
<body>
    <div class="message">
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the XSS vulnerability.</p>
    </div>
</body>
</html>
''')

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)