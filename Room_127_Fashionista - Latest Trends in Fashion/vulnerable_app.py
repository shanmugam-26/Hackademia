from flask import Flask, render_template_string, request, redirect

app = Flask(__name__)

# Security Misconfiguration: Default secret key is used
app.secret_key = 'defaultsecret'

main_page_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Fashionista - Latest Trends in Fashion</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; color: #555;}
        .container {width: 80%; margin: auto; overflow: hidden;}
        #showcase {background: url('https://via.placeholder.com/1200x400') no-repeat center center; min-height: 400px;}
        #showcase h1 {margin-top: 100px; color: #fff; text-align: center; font-size: 55px;}
        #newsletter {padding: 15px; color: #fff; background: #000;}
        #newsletter h1 {float: left;}
        #newsletter form {float: right; margin-top: 15px;}
        #newsletter input[type="email"] {padding: 4px; height: 25px; width: 250px;}
        .products {margin: 20px 0; overflow: hidden;}
        .product {float: left; width: 30%; margin: 1.66%;}
        .product img {width: 100%;}
        footer {background: #000; color: #fff; text-align: center; padding: 20px; margin-top: 20px;}
    </style>
</head>
<body>
    <header id="showcase">
        <h1>Welcome to Fashionista</h1>
    </header>
    <section id="newsletter">
        <div class="container">
            <h1>Subscribe To Our Newsletter</h1>
            <form>
                <input type="email" placeholder="Enter Email">
                <button type="submit">Subscribe</button>
            </form>
        </div>
    </section>
    <div class="container">
        <section class="products">
            <h2>Latest Products</h2>
            <div class="product">
                <img src="https://via.placeholder.com/300x300" alt="Product 1">
                <p>Stylish Dress</p>
            </div>
            <div class="product">
                <img src="https://via.placeholder.com/300x300" alt="Product 2">
                <p>Elegant Suit</p>
            </div>
            <div class="product">
                <img src="https://via.placeholder.com/300x300" alt="Product 3">
                <p>Casual Shirt</p>
            </div>
        </section>
    </div>
    <footer>
        <p>Fashionista &copy; 2023</p>
    </footer>
    <!-- The following comment is a hint for authorized personnel only -->
    <!-- TODO: Secure the admin panel at /admin -->
</body>
</html>
"""

login_page_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - Fashionista Admin</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4; color: #555;}
        .login-container {width: 300px; margin: 100px auto;}
        h2 {text-align: center;}
        form {display: flex; flex-direction: column;}
        input {margin: 5px 0; padding: 10px;}
        .error {color: red; text-align: center;}
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Admin Login</h2>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post">
            <input type="text" name="username" placeholder="Username" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

admin_page_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Panel - Fashionista</title>
    <style>
        body {font-family: Arial, sans-serif;}
        h1 {text-align: center;}
        .congrats {color: green; text-align: center; font-size: 24px;}
    </style>
</head>
<body>
    <h1>Admin Control Panel</h1>
    <p class="congrats">Congratulations! You have accessed the admin panel.</p>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(main_page_html)

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /admin"

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    # Security Misconfiguration: Hardcoded credentials
    if request.method == 'POST':
        if request.form['username'] == 'admin' and request.form['password'] == 'FashionRulez!':
            # Security Misconfiguration: Using predictable session cookie
            session['logged_in'] = True
            return redirect('/admin')
        else:
            error = 'Invalid credentials'
    return render_template_string(login_page_html, error=error)

@app.route('/admin')
def admin():
    # Security Misconfiguration: Flawed authentication check
    if session.get('logged_in'):
        return render_template_string(admin_page_html)
    else:
        # Security Misconfiguration: Exposed sensitive information in redirect
        return redirect('/login?next=/admin')

if __name__ == '__main__':
    from flask import session
    app.run(debug=True)