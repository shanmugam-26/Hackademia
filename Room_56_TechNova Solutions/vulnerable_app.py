from flask import Flask, request, render_template_string, redirect, url_for
import pickle

app = Flask(__name__)

# HTML template for the homepage
homepage = '''
<!DOCTYPE html>
<html>
<head>
    <title>TechNova Solutions</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #f4f4f4;}
        .container {width: 80%; margin: auto; overflow: hidden;}
        header {background: #50b3a2; color: #ffffff; padding-top: 30px; min-height: 70px; border-bottom: #3b8686 3px solid;}
        header a {color: #ffffff; text-decoration: none; text-transform: uppercase; font-size: 16px;}
        header ul {margin: 0; padding: 0;}
        header li {float: right; display: inline; padding: 0 20px 0 20px;}
        header #branding {float: left;}
        header #branding h1 {margin: 0;}
        footer {background: #50b3a2; color: #ffffff; text-align: center; padding: 20px; margin-top: 20px;}
        section {padding: 20px;}
        form {margin-top: 20px;}
        input[type="text"] {padding: 5px; width: 300px;}
        input[type="submit"] {padding: 5px 15px; background-color: #50b3a2; color: #fff; border: none;}
        p.result {background-color: #eaeaea; padding: 10px;}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div id="branding">
                <h1>TechNova Solutions</h1>
            </div>
            <nav>
                <ul>
                    <li><a href="/">Home</a></li>
                    <li><a href="/careers">Careers</a></li>
                    <li><a href="/about">About Us</a></li>
                </ul>
            </nav>
        </div>
    </header>
    <section>
        <div class="container">
            <h2>Welcome to TechNova Solutions</h2>
            <p>Innovating the future of technology. Join us in our mission to make the world a better place through cutting-edge solutions.</p>
            <form method="POST" action="/">
                <label for="data">Enter Data (for internal processing):</label><br><br>
                <input type="text" name="data" id="data" placeholder="Enter serialized data" required />
                <input type="submit" value="Submit" />
            </form>
            {% if result %}
                <p class="result">{{ result }}</p>
            {% endif %}
        </div>
    </section>
    <footer>
        <p>TechNova Solutions &copy; 2023</p>
    </footer>
</body>
</html>
'''

# Route for the homepage
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        data = request.form.get('data')
        try:
            obj = pickle.loads(data.encode('latin1'))
            result = "Data processed successfully."
        except Exception as e:
            result = "An error occurred: " + str(e)
        return render_template_string(homepage, result=result)
    return render_template_string(homepage)

# Route for careers page
@app.route('/careers')
def careers():
    return '<h1>Careers at TechNova Solutions</h1><p>We are always looking for talented individuals to join our team.</p>'

# Route for about page
@app.route('/about')
def about():
    return '<h1>About TechNova Solutions</h1><p>At TechNova Solutions, we are committed to innovation and excellence.</p>'

# Congratulations route
@app.route('/congrats')
def congrats():
    return '<h1>Congratulations!</h1><p>You have successfully exploited the vulnerability.</p>'

if __name__ == '__main__':
    app.run(debug=True)