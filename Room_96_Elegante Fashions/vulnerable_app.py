from flask import Flask, request, render_template_string, redirect, url_for
import base64

app = Flask(__name__)

@app.route('/')
def index():
    # Simulate an attractive fashion brand homepage
    page_html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Elegante Fashions</title>
        <style>
            body {font-family: Arial, sans-serif; margin:0; padding:0; }
            .header {background-color:#333; color:#fff; padding:20px; text-align:center;}
            .nav {overflow:hidden; background-color:#444;}
            .nav a {float:left; display:block; color:#fff; text-align:center; padding:14px 16px; text-decoration:none;}
            .nav a:hover {background-color:#ddd; color:#000;}
            .banner {background-image:url('https://example.com/banner.jpg'); background-size:cover; padding:100px; text-align:center; color:#fff;}
            .content {padding:20px;}
            .footer {background-color:#333; color:#fff; padding:10px; text-align:center;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Elegante Fashions</h1>
            <p>Unveiling the elegance in you</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/collection">Collection</a>
            <a href="/login">Login</a>
            <a href="/contact">Contact</a>
        </div>
        <div class="banner">
            <h2>Fall Collection 2023</h2>
            <p>Discover the trends of the season</p>
            <button onclick="window.location.href='/collection'">Explore Now</button>
        </div>
        <div class="content">
            <h3>About Us</h3>
            <p>At Elegante Fashions, we believe in timeless style and unparalleled quality...</p>
        </div>
        <div class="footer">
            &copy; 2023 Elegante Fashions. All rights reserved.
        </div>
    </body>
    </html>
    '''
    return render_template_string(page_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Insecure communication vulnerability
        # The credentials are sent over HTTP in plain text
        username = request.form.get('username')
        password = request.form.get('password')

        # Simulate credential check (accept any credentials)
        if username and password:
            # Insecurely store the credentials in a plain text file (vulnerability)
            with open('credentials.txt', 'a') as f:
                f.write(f'{username}:{password}\n')

            # Redirect to the welcome page
            return redirect(url_for('welcome'))
        else:
            error = 'Invalid credentials. Please try again.'
            return render_template_string(login_page_html, error=error)
    else:
        error = ''
    return render_template_string(login_page_html, error=error)

login_page_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Elegante Fashions - Login</title>
    <style>
        body {font-family: Arial, sans-serif; background-color:#f4f4f4; padding:50px;}
        .login-container {background-color:#fff; padding:20px; max-width:300px; margin:auto; border:1px solid #ccc;}
        .login-container h2 {text-align:center;}
        .login-container input[type=text], .login-container input[type=password] {
            width:100%; padding:12px; margin:8px 0; border:1px solid #ccc; box-sizing:border-box;
        }
        .login-container button {
            width:100%; background-color:#333; color:#fff; padding:14px 20px; margin:8px 0; border:none; cursor:pointer;
        }
        .login-container button:hover {
            background-color:#444;
        }
        .error {color:red; text-align:center;}
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Account Login</h2>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <form method="POST" action="/login">
            <label for="username">Username:</label>
            <input type="text" name="username" required/>
            <label for="password">Password:</label>
            <input type="password" name="password" required/>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
'''

@app.route('/welcome')
def welcome():
    # User arrives here after login
    # Include JavaScript that sends a secret code over an insecure channel
    secret_code = 's3cr3t_c0d3'
    encoded_secret = base64.b64encode(secret_code.encode()).decode()
    welcome_html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Elegante Fashions - Welcome</title>
    </head>
    <body>
        <h1>Welcome to Elegante Fashions!</h1>
        <p>Thank you for logging in. Explore our new collection.</p>
        <a href="/">Back to Home</a>
        <script>
            // Insecure communication: sending secret code over HTTP in plaintext
            var secret = atob("{encoded_secret}");
            var xhr = new XMLHttpRequest();
            xhr.open("POST", "/secret", true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify({{ 'secret': secret }}));
        </script>
    </body>
    </html>
    '''
    return render_template_string(welcome_html)

@app.route('/secret', methods=['POST'])
def secret():
    # Receives the secret code sent from the client-side JavaScript
    data = request.get_json()
    # Process the secret code (do nothing in this case)
    return '', 204

@app.route('/congratulations')
def congratulations():
    # User must provide correct secret code in query parameter 's' to access this page
    provided_secret = request.args.get('s', '')
    expected_secret = 's3cr3t_c0d3'
    if provided_secret == expected_secret:
        congrats_html = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Congratulations!</title>
        </head>
        <body>
            <h1>Congratulations!</h1>
            <p>You have successfully exploited the insecure communication vulnerability!</p>
            <p>Good job!</p>
        </body>
        </html>
        '''
        return render_template_string(congrats_html)
    else:
        return redirect('/')

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=False)