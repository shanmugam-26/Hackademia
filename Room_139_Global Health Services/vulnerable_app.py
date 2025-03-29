from flask import Flask, render_template_string, request

app = Flask(__name__)

# Hidden flag variable
flag = "Congratulations! You have successfully exploited the SSTI vulnerability."

@app.route('/')
def home():
    return '''
    <html>
        <head>
            <title>Global Health Services</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f0f8ff; margin: 0; padding: 0; }
                header { background-color: #2d2d72; padding: 20px; color: white; text-align: center; }
                nav { background-color: #444; overflow: hidden; }
                nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                        padding: 14px 16px; text-decoration: none; }
                nav a:hover { background-color: #ddd; color: black; }
                .container { padding: 20px; }
                h1 { color: #2d2d72; }
                p { font-size: 18px; }
                form { margin-top: 20px; }
                input[type=text] { padding: 10px; width: 300px; }
                input[type=submit] { padding: 10px 20px; }
                footer { background-color: #2d2d72; color: white; text-align: center;
                         padding: 10px; position: fixed; width: 100%; bottom: 0; }
            </style>
        </head>
        <body>
            <header>
                <h1>Global Health Services</h1>
            </header>
            <nav>
                <a href="/">Home</a>
                <a href="/about">About Us</a>
                <a href="/contact">Contact</a>
            </nav>
            <div class="container">
                <h2>Your health is our priority.</h2>
                <p>At Global Health Services, we provide top-notch healthcare services for you and your family.</p>
                <form action="/search" method="post">
                    <label for="doctor">Search for a Doctor:</label><br><br>
                    <input type="text" id="doctor" name="doctor" placeholder="Enter doctor's name"><br><br>
                    <input type="submit" value="Search">
                </form>
            </div>
            <footer>
                <p>&copy; 2023 Global Health Services</p>
            </footer>
        </body>
    </html>
    '''

@app.route('/search', methods=['POST'])
def search():
    doctor = request.form.get('doctor')
    template = '''
    <html>
        <head>
            <title>Search Results</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f0f8ff; margin: 0; padding: 0; }
                header { background-color: #2d2d72; padding: 20px; color: white; text-align: center; }
                nav { background-color: #444; overflow: hidden; }
                nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                        padding: 14px 16px; text-decoration: none; }
                nav a:hover { background-color: #ddd; color: black; }
                .container { padding: 20px; }
                h1 { color: #2d2d72; }
                p { font-size: 18px; }
                a { text-decoration: none; color: #2d2d72; }
                footer { background-color: #2d2d72; color: white; text-align: center;
                         padding: 10px; position: fixed; width: 100%; bottom: 0; }
            </style>
        </head>
        <body>
            <header>
                <h1>Global Health Services</h1>
            </header>
            <nav>
                <a href="/">Home</a>
                <a href="/about">About Us</a>
                <a href="/contact">Contact</a>
            </nav>
            <div class="container">
                <h2>Search Results for {{ doctor }}</h2>
                <p>No doctors found matching your search.</p>
                <a href="/">Go back</a>
            </div>
            <footer>
                <p>&copy; 2023 Global Health Services</p>
            </footer>
        </body>
    </html>
    '''
    return render_template_string(template, doctor=doctor)

@app.route('/about')
def about():
    return '''
    <html>
        <head>
            <title>About Us</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f0f8ff; margin: 0; padding: 0; }
                header { background-color: #2d2d72; padding: 20px; color: white; text-align: center; }
                nav { background-color: #444; overflow: hidden; }
                nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                        padding: 14px 16px; text-decoration: none; }
                nav a:hover { background-color: #ddd; color: black; }
                .container { padding: 20px; }
                h1 { color: #2d2d72; }
                p { font-size: 18px; }
                footer { background-color: #2d2d72; color: white; text-align: center;
                         padding: 10px; position: fixed; width: 100%; bottom: 0; }
            </style>
        </head>
        <body>
            <header>
                <h1>About Global Health Services</h1>
            </header>
            <nav>
                <a href="/">Home</a>
                <a href="/about">About Us</a>
                <a href="/contact">Contact</a>
            </nav>
            <div class="container">
                <p>Global Health Services has been providing world-class healthcare since 1990. Our team of dedicated professionals is here to serve you.</p>
                <a href="/">Go back</a>
            </div>
            <footer>
                <p>&copy; 2023 Global Health Services</p>
            </footer>
        </body>
    </html>
    '''

@app.route('/contact')
def contact():
    return '''
    <html>
        <head>
            <title>Contact Us</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f0f8ff; margin: 0; padding: 0; }
                header { background-color: #2d2d72; padding: 20px; color: white; text-align: center; }
                nav { background-color: #444; overflow: hidden; }
                nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                        padding: 14px 16px; text-decoration: none; }
                nav a:hover { background-color: #ddd; color: black; }
                .container { padding: 20px; }
                h1 { color: #2d2d72; }
                p { font-size: 18px; }
                footer { background-color: #2d2d72; color: white; text-align: center;
                         padding: 10px; position: fixed; width: 100%; bottom: 0; }
            </style>
        </head>
        <body>
            <header>
                <h1>Contact Global Health Services</h1>
            </header>
            <nav>
                <a href="/">Home</a>
                <a href="/about">About Us</a>
                <a href="/contact">Contact</a>
            </nav>
            <div class="container">
                <p>Phone: (555) 123-4567</p>
                <p>Email: info@globalhealthservices.com</p>
                <a href="/">Go back</a>
            </div>
            <footer>
                <p>&copy; 2023 Global Health Services</p>
            </footer>
        </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(debug=True)