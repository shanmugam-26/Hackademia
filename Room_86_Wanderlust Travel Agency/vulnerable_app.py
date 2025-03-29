from flask import Flask, render_template_string, request, redirect, url_for, Response
import requests

app = Flask(__name__)

# Main page template
main_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Wanderlust Travel Agency</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f6f6f6; margin: 0; padding: 0; }
        header { background-color: #333; color: #fff; padding: 20px; text-align: center; }
        nav ul { list-style-type: none; margin: 0; padding: 0; overflow: hidden; background-color: #444; }
        nav li { float: left; }
        nav li a { display: block; color: white; text-align: center; padding: 14px 16px; text-decoration: none; }
        nav li a:hover { background-color: #111; }
        .banner { background-image: url('https://example.com/banner.jpg'); background-size: cover; height: 300px; }
        .content { padding: 20px; }
        .destination { display: inline-block; width: 30%; margin: 1%; vertical-align: top; }
        .destination img { width: 100%; height: 200px; object-fit: cover; }
    </style>
</head>
<body>
    <header>
        <h1>Wanderlust Travel Agency</h1>
    </header>
    <nav>
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/destinations">Destinations</a></li>
            <li><a href="/specials">Special Offers</a></li>
            <li><a href="/contact">Contact Us</a></li>
        </ul>
    </nav>
    <div class="banner"></div>
    <div class="content">
        <h2>Explore the World with Us!</h2>
        <p>Discover amazing places at exclusive deals.</p>
        <h3>Featured Destinations</h3>
        <div class="destination">
            <img src="/destination?place=paris" alt="Paris">
            <h4>Paris</h4>
        </div>
        <div class="destination">
            <img src="/destination?place=newyork" alt="New York">
            <h4>New York</h4>
        </div>
        <div class="destination">
            <img src="/destination?place=tokyo" alt="Tokyo">
            <h4>Tokyo</h4>
        </div>
    </div>
</body>
</html>
'''

congrats_page = '''
<!DOCTYPE html>
<html>
<head>
    <title>Congratulations!</title>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the vulnerability.</p>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(main_page)

@app.route('/destination')
def destination():
    place = request.args.get('place', '')
    url = request.args.get('url')
    if url:
        try:
            response = requests.get(url)
            content_type = response.headers.get('Content-Type', 'text/plain')
            if 'Congratulations' in response.text:
                return redirect(url_for('congratulations'))
            return Response(response.content, content_type=content_type)
        except:
            return 'Invalid URL', 400
    else:
        # Default behavior is to fetch image from a constructed URL based on 'place'
        url = 'https://example.com/images/' + place + '.jpg'
        try:
            response = requests.get(url)
            content_type = response.headers.get('Content-Type', 'image/jpeg')
            return Response(response.content, content_type=content_type)
        except:
            return 'Image not found', 404

@app.route('/admin')
def admin():
    # Secret admin page that should not be accessible
    return 'Congratulations! You have found the secret admin page.'

@app.route('/congratulations')
def congratulations():
    return render_template_string(congrats_page)

@app.route('/destinations')
def destinations():
    # Additional page for navigation
    return render_template_string('<h1>Our Destinations</h1><p>Under construction.</p>')

@app.route('/specials')
def specials():
    # Additional page for navigation
    return render_template_string('<h1>Special Offers</h1><p>Under construction.</p>')

@app.route('/contact')
def contact():
    # Additional page for navigation
    return render_template_string('<h1>Contact Us</h1><p>Under construction.</p>')

if __name__ == '__main__':
    app.run(debug=True)