from flask import Flask, request, render_template_string, make_response
import pickle
import base64

app = Flask(__name__)

@app.route('/')
def home():
    user = None
    session_cookie = request.cookies.get('session')
    if session_cookie:
        try:
            session_data = pickle.loads(base64.b64decode(session_cookie))
            user = session_data.get('user')
        except:
            user = 'Guest'
    else:
        session_data = {'user': 'Guest'}
        session_cookie = base64.b64encode(pickle.dumps(session_data)).decode()
    response = make_response(render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Acme Software Solutions</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
        .header { background-color: #0073e6; color: white; padding: 20px; text-align: center; }
        .content { margin: 20px; }
        .footer { background-color: #ddd; padding: 10px; text-align: center; }
        nav ul { list-style-type: none; padding: 0; }
        nav ul li { display: inline; margin-right: 15px; }
        nav a { text-decoration: none; color: white; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Acme Software Solutions</h1>
        <p>Innovative solutions for modern problems</p>
        <nav>
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="/products">Products</a></li>
                <li><a href="/careers">Careers</a></li>
                <li><a href="/contact">Contact Us</a></li>
            </ul>
        </nav>
    </div>
    <div class="content">
        <h2>Welcome {{ user }}</h2>
        <p>At Acme Software Solutions, we specialize in creating cutting-edge software tailored to your needs.</p>
        <p>Our team of experts is dedicated to delivering high-quality products and exceptional customer service.</p>
        <p>Explore our website to learn more about what we offer.</p>
        {% if user == 'admin' %}
            <h3>Congratulations!</h3>
            <p>You've successfully exploited the vulnerability.</p>
        {% endif %}
    </div>
    <div class="footer">
        &copy; 2023 Acme Software Solutions
    </div>
</body>
</html>
    ''', user=user))
    if not request.cookies.get('session'):
        response.set_cookie('session', session_cookie)
    return response

if __name__ == '__main__':
    app.run(debug=True)