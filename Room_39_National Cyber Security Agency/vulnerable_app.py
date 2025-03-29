from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    homepage_html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>National Cyber Security Agency</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0;}
            header {background-color: #0b3d91; color: white; padding: 20px;}
            nav {background-color: #333; overflow: hidden;}
            nav a {float: left; display: block; color: #f2f2f2; text-align: center;
                   padding: 14px 16px; text-decoration: none;}
            nav a:hover {background-color: #ddd; color: black;}
            section {padding:20px;}
            footer {background-color: #0b3d91; color: white; text-align: center; padding: 10px; position:fixed; bottom:0; width:100%;}
        </style>
    </head>
    <body>
        <header>
            <h1>National Cyber Security Agency</h1>
            <p>Protecting the nation's cyberspace</p>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/news">News</a>
            <a href="/contact">Contact</a>
            <a href="/login">Login</a>
        </nav>
        <section>
            <h2>Welcome to the National Cyber Security Agency</h2>
            <p>Our mission is to secure and protect the nation's critical cyber infrastructure.
            We work around the clock to guard against cyber threats and provide resources
            for cybersecurity awareness and education.</p>
        </section>
        <footer>
            &copy; 2023 National Cyber Security Agency
        </footer>
    </body>
    </html>
    '''
    return render_template_string(homepage_html)

@app.route('/news')
def news():
    news_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>News - National Cyber Security Agency</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0;}
            header {background-color: #0b3d91; color: white; padding: 20px;}
            nav {background-color: #333; overflow: hidden;}
            nav a {float: left; display: block; color: #f2f2f2; text-align: center;
                   padding: 14px 16px; text-decoration: none;}
            nav a:hover {background-color: #ddd; color: black;}
            section {padding:20px;}
            footer {background-color: #0b3d91; color: white; text-align: center; padding: 10px; position:fixed; bottom:0; width:100%;}
        </style>
    </head>
    <body>
        <header>
            <h1>National Cyber Security Agency</h1>
            <p>Protecting the nation's cyberspace</p>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/news">News</a>
            <a href="/contact">Contact</a>
            <a href="/login">Login</a>
        </nav>
        <section>
            <h2>Latest News</h2>
            <p><strong>October 1, 2023:</strong> NCSA launches new cybersecurity initiative to protect critical infrastructure.</p>
            <p><strong>September 15, 2023:</strong> Collaborative efforts with international partners strengthen global cyber defense.</p>
        </section>
        <footer>
            &copy; 2023 National Cyber Security Agency
        </footer>
    </body>
    </html>
    '''
    return render_template_string(news_page)

@app.route('/contact')
def contact():
    contact_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - National Cyber Security Agency</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0;}
            header {background-color: #0b3d91; color: white; padding: 20px;}
            nav {background-color: #333; overflow: hidden;}
            nav a {float: left; display: block; color: #f2f2f2; text-align: center;
                   padding: 14px 16px; text-decoration: none;}
            nav a:hover {background-color: #ddd; color: black;}
            section {padding:20px;}
            footer {background-color: #0b3d91; color: white; text-align: center; padding: 10px; position:fixed; bottom:0; width:100%;}
            form {max-width: 500px; margin: auto;}
            input[type=text], textarea {width: 100%; padding: 12px; margin: 8px 0; box-sizing: border-box;}
            input[type=submit] {background-color: #0b3d91; color: white; padding: 12px 20px; border: none; cursor: pointer;}
            input[type=submit]:hover {background-color: #333;}
        </style>
    </head>
    <body>
        <header>
            <h1>National Cyber Security Agency</h1>
            <p>Protecting the nation's cyberspace</p>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/news">News</a>
            <a href="/contact">Contact</a>
            <a href="/login">Login</a>
        </nav>
        <section>
            <h2>Contact Us</h2>
            <form>
                <label for="name">Name:</label><br>
                <input type="text" id="name" name="name"><br>
                <label for="email">Email:</label><br>
                <input type="text" id="email" name="email"><br>
                <label for="message">Message:</label><br>
                <textarea id="message" name="message" rows="4"></textarea><br><br>
                <input type="submit" value="Submit">
            </form>
        </section>
        <footer>
            &copy; 2023 National Cyber Security Agency
        </footer>
    </body>
    </html>
    '''
    return render_template_string(contact_page)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Assume login is always successful for simplicity
        next_url = request.form.get('next')
        if next_url:
            return redirect(next_url)
        else:
            return redirect('/')
    else:
        next_url = request.args.get('next', '/')
        login_form = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - National Cyber Security Agency</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin:0;}
                .login-container {width: 300px; margin: auto; padding-top: 100px;}
                input[type=text], input[type=password] {width: 100%; padding: 12px 20px;
                    margin: 8px 0; box-sizing: border-box;}
                input[type=submit] {width: 100%; background-color: #0b3d91; color: white;
                    padding: 14px 20px; margin: 8px 0; border: none; cursor: pointer;}
                input[type=submit]:hover {background-color: #333;}
            </style>
        </head>
        <body>
            <div class="login-container">
                <h2>Login</h2>
                <form method="post">
                    <input type="hidden" name="next" value="{next_url}">
                    <label for="username">Username:</label><br>
                    <input type="text" id="username" name="username"><br>
                    <label for="password">Password:</label><br>
                    <input type="password" id="password" name="password"><br><br>
                    <input type="submit" value="Login">
                </form>
            </div>
        </body>
        </html>
        '''.format(next_url=next_url)
        return render_template_string(login_form)

@app.route('/congrats')
def congrats():
    congrats_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Congratulations!</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4; text-align:center; padding-top: 100px;}
            h1 {color: green;}
        </style>
    </head>
    <body>
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the unvalidated redirect vulnerability!</p>
    </body>
    </html>
    '''
    return render_template_string(congrats_page)

if __name__ == '__main__':
    app.run(debug=False)