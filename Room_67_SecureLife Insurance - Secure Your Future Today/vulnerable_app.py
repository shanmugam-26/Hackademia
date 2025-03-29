from flask import Flask, request, render_template_string, make_response
import pickle
import base64

app = Flask(__name__)

FLAG = False  # Global variable to check if the vulnerability has been exploited

@app.route('/')
def index():
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>SecureLife Insurance - Secure Your Future Today</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0; padding:0;}
            header {background-color: #004c99; color: white; padding: 20px;}
            nav ul {list-style-type: none; margin: 0; padding: 0; overflow: hidden;}
            nav li {float: left; margin-right: 10px;}
            nav li a {color: white; text-decoration: none; padding: 14px 16px;}
            nav li a:hover {background-color: #003366;}
            .container {padding: 20px;}
            footer {background-color: #004c99; color: white; text-align: center; padding: 10px; position: fixed; bottom:0; width:100%;}
        </style>
    </head>
    <body>
        <header>
            <h1>SecureLife Insurance</h1>
            <nav>
                <ul>
                    <li><a href="/">Home</a></li>
                    <li><a href="/profile">My Profile</a></li>
                    <li><a href="/contact">Contact Us</a></li>
                </ul>
            </nav>
        </header>
        <div class="container">
            <h2>Welcome to SecureLife Insurance</h2>
            <p>Your trusted partner in securing a better future for you and your loved ones.</p>
            <p>At SecureLife Insurance, we offer a wide range of insurance products to meet all your needs. Protect what matters most with our comprehensive coverage options.</p>
        </div>
        <footer>
            &copy; 2023 SecureLife Insurance
        </footer>
    </body>
    </html>
    ''')

@app.route('/profile')
def profile():
    global FLAG  # Use global to modify the FLAG variable
    session_cookie = request.cookies.get('session')
    if session_cookie:
        try:
            session_data = pickle.loads(base64.b64decode(session_cookie))
            name = session_data.get('name', 'Guest')

            if FLAG:
                # Congratulation message for successful exploitation
                return render_template_string('''
                <!doctype html>
                <html>
                <head>
                    <title>Congratulations!</title>
                    <style>
                        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0; padding:0;}
                        header {background-color: #004c99; color: white; padding: 20px;}
                        nav ul {list-style-type: none; margin: 0; padding: 0; overflow: hidden;}
                        nav li {float: left; margin-right: 10px;}
                        nav li a {color: white; text-decoration: none; padding: 14px 16px;}
                        nav li a:hover {background-color: #003366;}
                        .container {padding: 20px;}
                        footer {background-color: #004c99; color: white; text-align: center; padding: 10px; position: fixed; bottom:0; width:100%;}
                    </style>
                </head>
                <body>
                    <header>
                        <h1>SecureLife Insurance</h1>
                        <nav>
                            <ul>
                                <li><a href="/">Home</a></li>
                                <li><a href="/profile">My Profile</a></li>
                                <li><a href="/contact">Contact Us</a></li>
                            </ul>
                        </nav>
                    </header>
                    <div class="container">
                        <h2>Congratulations!</h2>
                        <p>You have successfully exploited the vulnerability!</p>
                    </div>
                    <footer>
                        &copy; 2023 SecureLife Insurance
                    </footer>
                </body>
                </html>
                ''')
            else:
                return render_template_string('''
                <!doctype html>
                <html>
                <head>
                    <title>Your Profile - SecureLife Insurance</title>
                    <style>
                        body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0; padding:0;}
                        header {background-color: #004c99; color: white; padding: 20px;}
                        nav ul {list-style-type: none; margin: 0; padding: 0; overflow: hidden;}
                        nav li {float: left; margin-right: 10px;}
                        nav li a {color: white; text-decoration: none; padding: 14px 16px;}
                        nav li a:hover {background-color: #003366;}
                        .container {padding: 20px;}
                        footer {background-color: #004c99; color: white; text-align: center; padding: 10px; position: fixed; bottom:0; width:100%;}
                    </style>
                </head>
                <body>
                    <header>
                        <h1>SecureLife Insurance</h1>
                        <nav>
                            <ul>
                                <li><a href="/">Home</a></li>
                                <li><a href="/profile">My Profile</a></li>
                                <li><a href="/contact">Contact Us</a></li>
                            </ul>
                        </nav>
                    </header>
                    <div class="container">
                        <h2>Welcome back, {{name}}!</h2>
                        <p>Here is your profile information:</p>
                        <ul>
                            <li>Name: {{name}}</li>
                            <li>Policy Number: {{session_data.get('policy_number', 'N/A')}}</li>
                            <li>Account Balance: ${{session_data.get('balance', '0.00')}}</li>
                        </ul>
                    </div>
                    <footer>
                        &copy; 2023 SecureLife Insurance
                    </footer>
                </body>
                </html>
                ''', name=name, session_data=session_data)
        except Exception as e:
            return 'Error loading session data.'
    else:
        # Create a default session cookie for first-time visitors
        session_data = {'name': 'Guest', 'policy_number': 'N/A', 'balance': '0.00'}
        session_cookie = base64.b64encode(pickle.dumps(session_data)).decode('utf-8')
        resp = make_response(render_template_string('''
        <!doctype html>
        <html>
        <head>
            <title>Your Profile - SecureLife Insurance</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0; padding:0;}
                header {background-color: #004c99; color: white; padding: 20px;}
                nav ul {list-style-type: none; margin: 0; padding: 0; overflow: hidden;}
                nav li {float: left; margin-right: 10px;}
                nav li a {color: white; text-decoration: none; padding: 14px 16px;}
                nav li a:hover {background-color: #003366;}
                .container {padding: 20px;}
                footer {background-color: #004c99; color: white; text-align: center; padding: 10px; position: fixed; bottom:0; width:100%;}
            </style>
        </head>
        <body>
            <header>
                <h1>SecureLife Insurance</h1>
                <nav>
                    <ul>
                        <li><a href="/">Home</a></li>
                        <li><a href="/profile">My Profile</a></li>
                        <li><a href="/contact">Contact Us</a></li>
                    </ul>
                </nav>
            </header>
            <div class="container">
                <h2>Welcome, Guest!</h2>
                <p>Please log in to view your profile.</p>
            </div>
            <footer>
                &copy; 2023 SecureLife Insurance
            </footer>
        </body>
        </html>
        '''))
        resp.set_cookie('session', session_cookie)
        return resp

@app.route('/contact')
def contact():
    return render_template_string('''
    <!doctype html>
    <html>
    <head>
        <title>Contact Us - SecureLife Insurance</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0; padding:0;}
            header {background-color: #004c99; color: white; padding: 20px;}
            nav ul {list-style-type: none; margin: 0; padding: 0; overflow: hidden;}
            nav li {float: left; margin-right: 10px;}
            nav li a {color: white; text-decoration: none; padding: 14px 16px;}
            nav li a:hover {background-color: #003366;}
            .container {padding: 20px;}
            footer {background-color: #004c99; color: white; text-align: center; padding: 10px; position: fixed; bottom:0; width:100%;}
        </style>
    </head>
    <body>
        <header>
            <h1>SecureLife Insurance</h1>
            <nav>
                <ul>
                    <li><a href="/">Home</a></li>
                    <li><a href="/profile">My Profile</a></li>
                    <li><a href="/contact">Contact Us</a></li>
                </ul>
            </nav>
        </header>
        <div class="container">
            <h2>Contact Us</h2>
            <p>For any inquiries, please reach out to us at:</p>
            <ul>
                <li>Email: support@securelife.com</li>
                <li>Phone: +1 (555) 123-4567</li>
                <li>Address: 1234 Insurance Way, Suite 100, Anytown, USA</li>
            </ul>
        </div>
        <footer>
            &copy; 2023 SecureLife Insurance
        </footer>
    </body>
    </html>
    ''')

if __name__ == '__main__':
    app.run(debug=True)