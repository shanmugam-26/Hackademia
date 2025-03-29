from flask import Flask, render_template_string, request, redirect

app = Flask(__name__)

# Template for the home page
home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Anderson & Parker Law Firm</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        header { background-color: #2c3e50; color: #ecf0f1; padding: 20px; }
        nav ul { list-style-type: none; padding: 0; }
        nav li { display: inline; margin-right: 15px; }
        nav a { color: #ecf0f1; text-decoration: none; font-weight: bold; }
        main { padding: 20px; }
        footer { background-color: #2c3e50; color: #ecf0f1; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
        .button { background-color: #2980b9; color: white; padding: 10px 15px; text-decoration: none; }
    </style>
</head>
<body>
    <header>
        <h1>Anderson & Parker Law Firm</h1>
        <nav>
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="/about">About Us</a></li>
                <li><a href="/services">Our Services</a></li>
                <li><a href="/contact?next=/">Contact Us</a></li>
            </ul>
        </nav>
    </header>
    <main>
        <h2>Welcome to Anderson & Parker</h2>
        <p>At Anderson & Parker, we provide comprehensive legal solutions tailored to your needs.</p>
        <p><a href="/contact?next=/" class="button">Get in Touch</a></p>
    </main>
    <footer>
        &copy; 2023 Anderson & Parker Law Firm
    </footer>
</body>
</html>
'''

# Template for the contact page
contact_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Contact Us - Anderson & Parker Law Firm</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        header { background-color: #2c3e50; color: #ecf0f1; padding: 20px; }
        nav ul { list-style-type: none; padding: 0; }
        nav li { display: inline; margin-right: 15px; }
        nav a { color: #ecf0f1; text-decoration: none; font-weight: bold; }
        main { padding: 20px; }
        footer { background-color: #2c3e50; color: #ecf0f1; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
        label { display: block; margin-top: 10px; }
        input[type="text"], input[type="email"], textarea { width: 100%; padding: 8px; margin-top: 5px; }
        button { background-color: #2980b9; color: white; padding: 10px 15px; border: none; margin-top: 10px; }
    </style>
</head>
<body>
    <header>
        <h1>Anderson & Parker Law Firm</h1>
        <nav>
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="/about">About Us</a></li>
                <li><a href="/services">Our Services</a></li>
                <li><a href="/contact?next=/">Contact Us</a></li>
            </ul>
        </nav>
    </header>
    <main>
        <h2>Contact Us</h2>
        <form action="/submit" method="POST">
            <label>Name:
                <input type="text" name="name" required>
            </label>
            <label>Email:
                <input type="email" name="email" required>
            </label>
            <label>Message:
                <textarea name="message" rows="5" required></textarea>
            </label>
            <input type="hidden" name="next" value="{{ next }}">
            <button type="submit">Send Message</button>
        </form>
    </main>
    <footer>
        &copy; 2023 Anderson & Parker Law Firm
    </footer>
</body>
</html>
'''

# Template for the about page
about_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>About Us - Anderson & Parker Law Firm</title>
    <style>
        /* Reuse styles from previous templates */
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        header { background-color: #2c3e50; color: #ecf0f1; padding: 20px; }
        nav ul { list-style-type: none; padding: 0; }
        nav li { display: inline; margin-right: 15px; }
        nav a { color: #ecf0f1; text-decoration: none; font-weight: bold; }
        main { padding: 20px; }
        footer { background-color: #2c3e50; color: #ecf0f1; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <header>
        <h1>Anderson & Parker Law Firm</h1>
        <nav>
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="/about">About Us</a></li>
                <li><a href="/services">Our Services</a></li>
                <li><a href="/contact?next=/">Contact Us</a></li>
            </ul>
        </nav>
    </header>
    <main>
        <h2>About Us</h2>
        <p>With over 50 years of combined experience, Anderson & Parker is committed to excellence in legal services.</p>
    </main>
    <footer>
        &copy; 2023 Anderson & Parker Law Firm
    </footer>
</body>
</html>
'''

# Template for the services page
services_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Our Services - Anderson & Parker Law Firm</title>
    <style>
        /* Reuse styles from previous templates */
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background-color: #f4f4f4; }
        header { background-color: #2c3e50; color: #ecf0f1; padding: 20px; }
        nav ul { list-style-type: none; padding: 0; }
        nav li { display: inline; margin-right: 15px; }
        nav a { color: #ecf0f1; text-decoration: none; font-weight: bold; }
        main { padding: 20px; }
        footer { background-color: #2c3e50; color: #ecf0f1; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
        ul { list-style-type: square; }
    </style>
</head>
<body>
    <header>
        <h1>Anderson & Parker Law Firm</h1>
        <nav>
            <ul>
                <li><a href="/">Home</a></li>
                <li><a href="/about">About Us</a></li>
                <li><a href="/services">Our Services</a></li>
                <li><a href="/contact?next=/">Contact Us</a></li>
            </ul>
        </nav>
    </header>
    <main>
        <h2>Our Services</h2>
        <ul>
            <li>Corporate Law</li>
            <li>Family Law</li>
            <li>Intellectual Property</li>
            <li>Civil Litigation</li>
        </ul>
    </main>
    <footer>
        &copy; 2023 Anderson & Parker Law Firm
    </footer>
</body>
</html>
'''

# Template for the congratulations page
congrats_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding-top: 50px; background-color: #2ecc71; color: white; }
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the unvalidated redirect vulnerability.</p>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/about')
def about():
    return render_template_string(about_page)

@app.route('/services')
def services():
    return render_template_string(services_page)

@app.route('/contact')
def contact():
    next_url = request.args.get('next', '/')
    return render_template_string(contact_page, next=next_url)

@app.route('/submit', methods=['POST'])
def submit():
    # Process form data (omitted for brevity)
    next_url = request.form.get('next', '/')
    # Vulnerable redirect without validation
    return redirect(next_url)

@app.route('/congratulations')
def congratulations():
    return render_template_string(congrats_page)

if __name__ == '__main__':
    app.run(debug=False)