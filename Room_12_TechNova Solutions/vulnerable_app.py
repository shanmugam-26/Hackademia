from flask import Flask, render_template_string, request, redirect
app = Flask(__name__)

@app.route('/')
def index():
    home_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>TechNova Solutions</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0;}
            header {background-color: #4CAF50; padding: 20px; text-align: center;}
            nav {overflow: hidden; background-color: #333;}
            nav a {float: left; display: block; color: #f2f2f2; text-align: center;
                    padding: 14px 16px; text-decoration: none;}
            nav a:hover {background-color: #ddd; color: black;}
            section {padding: 20px;}
            footer {background-color: #333; color: white; text-align: center; padding: 10px;}
        </style>
    </head>
    <body>
        <header>
            <h1>Welcome to TechNova Solutions</h1>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/about">About Us</a>
            <a href="/services">Services</a>
            <a href="/careers">Careers</a>
            <a href="/contact">Contact Us</a>
            <a href="/login">Employee Login</a>
        </nav>
        <section>
            <h2>Innovative Technology Solutions for Modern Businesses</h2>
            <p>At TechNova Solutions, we specialize in delivering state-of-the-art technology solutions that drive
            business success. Our team of experts is dedicated to providing customized solutions that meet the unique
            needs of each client.</p>
        </section>
        <footer>
            <p>&copy; 2023 TechNova Solutions. All rights reserved.</p>
        </footer>
    </body>
    </html>
    '''
    return render_template_string(home_page)

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Employee Login - TechNova Solutions</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f2f2f2;}
            .login-container {width: 300px; padding: 16px; background-color: white; margin: auto; margin-top: 100px; border: solid 1px #ccc;}
            input[type=text], input[type=password] {width: 100%; padding: 12px 20px; margin: 8px 0;
            display: inline-block; border: 1px solid #ccc; box-sizing: border-box;}
            button {background-color: #4CAF50; color: white; padding: 14px 20px; margin: 8px 0;
            border: none; cursor: pointer; width: 100%;}
            button:hover {opacity: 0.8;}
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2>Employee Login</h2>
            <form action="/login" method="post">
                <label><b>Username</b></label>
                <input type="text" placeholder="Enter Username" name="username" required>

                <label><b>Password</b></label>
                <input type="password" placeholder="Enter Password" name="password" required>

                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    '''
    if request.method == 'POST':
        return redirect('/dashboard')
    return render_template_string(login_page)

@app.route('/dashboard')
def dashboard():
    dashboard_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard - TechNova Solutions</title>
    </head>
    <body>
        <h1>Employee Dashboard</h1>
        <p>Welcome to your dashboard.</p>
        <p><a href="/redirect?url=/confidential">Access Confidential Documents</a></p>
    </body>
    </html>
    '''
    return render_template_string(dashboard_page)

@app.route('/redirect')
def unsafe_redirect():
    url = request.args.get('url')
    if url:
        return redirect(url)
    else:
        return redirect('/')

@app.route('/confidential')
def confidential():
    confidential_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Confidential Documents - TechNova Solutions</title>
    </head>
    <body>
        <h1>Access Denied</h1>
        <p>You do not have the necessary permissions to view this page.</p>
    </body>
    </html>
    '''
    return render_template_string(confidential_page)

@app.route('/congratulations')
def congratulations():
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
    return render_template_string(congrats_page)

if __name__ == '__main__':
    app.run(debug=True)