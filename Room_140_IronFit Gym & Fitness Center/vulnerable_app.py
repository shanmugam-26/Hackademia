from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>IronFit Gym & Fitness Center</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
            .header { background-color: #ff4d4d; color: #fff; padding: 20px; text-align: center; }
            .nav { overflow: hidden; background-color: #333; }
            .nav a { float: left; display: block; color: #f2f2f2; text-align: center; padding: 14px 16px; text-decoration: none; }
            .nav a:hover { background-color: #ddd; color: black; }
            .banner { width: 100%; }
            .content { padding: 20px; }
            .footer { background-color: #333; color: #fff; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome to IronFit Gym & Fitness Center</h1>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/classes">Classes</a>
            <a href="/trainers">Trainers</a>
            <a href="/contact">Contact</a>
        </div>
        <div class="content">
            <img class="banner" src="/banner?image_url=http://example.com/banner.jpg" alt="Fitness Banner">
            <h2>Achieve Your Fitness Goals with Us</h2>
            <p>Join IronFit today and start your journey towards a healthier, happier you. Our state-of-the-art facilities and professional trainers are here to support you every step of the way.</p>
        </div>
        <div class="footer">
            &copy; 2023 IronFit Gym & Fitness Center
        </div>
    </body>
    </html>
    ''')

@app.route('/banner')
def banner():
    image_url = request.args.get('image_url')
    if image_url:
        try:
            response = requests.get(image_url)
            return response.content, response.status_code, {'Content-Type': response.headers['Content-Type']}
        except Exception:
            return 'Error loading image.', 500
    else:
        return 'No image URL provided.', 400

@app.route('/classes')
def classes():
    return '<h2>Our Classes</h2><p>We offer Yoga, Pilates, Zumba, and more!</p>'

@app.route('/trainers')
def trainers():
    return '<h2>Meet Our Trainers</h2><p>Our certified trainers are here to help you.</p>'

@app.route('/contact')
def contact():
    return '<h2>Contact Us</h2><p>Email: info@ironfit.com | Phone: (123) 456-7890</p>'

@app.errorhandler(403)
def forbidden(e):
    return 'Congratulations! You have exploited the SSRF vulnerability.', 200

if __name__ == '__main__':
    app.run(debug=True)