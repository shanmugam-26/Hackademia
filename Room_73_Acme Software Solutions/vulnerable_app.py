from flask import Flask, render_template_string, request, redirect

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Acme Software Solutions</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f5f5f5; margin:0; padding:0;}
            header {background-color: #4CAF50; color: white; padding: 20px; text-align: center;}
            nav {display: flex; justify-content: center; background-color: #333;}
            nav a {color: white; padding: 14px 20px; text-decoration: none;}
            nav a:hover {background-color: #ddd; color: black;}
            .container {padding: 20px;}
            footer {background-color: #4CAF50; color: white; text-align: center; padding: 10px;}
        </style>
    </head>
    <body>
        <header>
            <h1>Acme Software Solutions</h1>
        </header>
        <nav>
            <a href="/">Home</a>
            <a href="/products">Products</a>
            <a href="/solutions">Solutions</a>
            <a href="/careers">Careers</a>
            <a href="/contact">Contact Us</a>
        </nav>
        <div class="container">
            <h2>Welcome to Acme Software Solutions</h2>
            <p>At Acme, we deliver innovative software solutions to help your business thrive in the digital era.</p>
            <p>We value your feedback. Please leave your comments below:</p>
            <form action="/feedback" method="post">
                <textarea name="feedback" placeholder="Enter your feedback here..." cols="60" rows="5"></textarea><br><br>
                <input type="submit" value="Submit Feedback">
            </form>
        </div>
        <footer>
            &copy; 2023 Acme Software Solutions. All rights reserved.
        </footer>
    </body>
    </html>
    '''

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        user_feedback = request.form.get('feedback', '')
        if user_feedback:
            secret_flag = 'Congratulations! You have uncovered the secret flag: FLAG{SSTI_Exploited}'
            template = f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Thank You for Your Feedback</title>
            </head>
            <body>
                <h2>Your Feedback:</h2>
                {user_feedback}
            </body>
            </html>
            '''
            # Vulnerable endpoint intentionally using user input directly in the template
            return render_template_string(template)
        else:
            return redirect('/')
    else:
        return redirect('/')

if __name__ == '__main__':
    app.run(debug=Fals)