from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    feedback = ''
    if request.method == 'POST':
        name = request.form.get('name', '')
        message = request.form.get('message', '')
        feedback = f"<p><strong>{name}</strong> says: {message}</p>"
    page = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>PrimeFit Health Club</title>
        <style>
            body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #fff; color: #333; margin: 0; padding: 0; }}
            header, footer {{ background-color: #444; color: #fff; padding: 20px 0; }}
            .container {{ width: 80%; margin: auto; overflow: hidden; }}
            header h1 {{ margin: 0; }}
            nav {{ float: right; }}
            nav ul {{ list-style: none; margin: 0; padding: 0; }}
            nav li {{ display: inline; margin-left: 20px; }}
            nav a {{ color: #fff; text-decoration: none; font-weight: bold; }}
            #showcase {{ background: url('https://via.placeholder.com/1200x400') no-repeat center; min-height: 400px; }}
            #showcase .content {{ position: relative; top: 50%; transform: translateY(-50%); text-align: center; color: #fff; }}
            #showcase h1 {{ font-size: 55px; margin-bottom: 10px; }}
            #showcase p {{ font-size: 20px; }}
            .content-section {{ padding: 20px 0; }}
            .content-section h2 {{ text-align: center; margin-bottom: 20px; }}
            .feedback {{ background: #f4f4f4; padding: 20px; margin-bottom: 20px; }}
            .feedback p {{ margin: 0; }}
            form p {{ margin-bottom: 10px; }}
            form label {{ display: block; }}
            form input, form textarea {{ width: 100%; padding: 8px; }}
            form button {{ padding: 10px 15px; background: #50b3a2; color: #fff; border: 0; }}
            footer p {{ text-align: center; }}
            @media(max-width: 768px) {{
                nav {{ float: none; }}
                nav ul {{ text-align: center; }}
                nav li {{ display: block; margin: 0; }}
            }}
        </style>
    </head>
    <body>
        <header>
            <div class="container">
                <h1>PrimeFit Health Club</h1>
                <nav>
                    <ul>
                        <li><a href="/">Home</a></li>
                        <li><a href="/classes">Classes</a></li>
                        <li><a href="/membership">Membership</a></li>
                        <li><a href="/contact">Contact Us</a></li>
                    </ul>
                </nav>
            </div>
        </header>
        <section id="showcase">
            <div class="content">
                <h1>Get Fit, Stay Healthy</h1>
                <p>Your journey to a better life starts here.</p>
            </div>
        </section>
        <section class="content-section">
            <div class="container">
                <h2>Join Our Community</h2>
                <p>At PrimeFit Health Club, we believe in fostering a supportive and motivating environment where everyone can reach their fitness goals. With state-of-the-art equipment, expert trainers, and a variety of classes, we're here to help you every step of the way.</p>
            </div>
        </section>
        <section class="content-section">
            <div class="container">
                <h2>Member Feedback</h2>
                <div class="feedback">
                    {{ feedback|safe }}
                </div>
                <form method="post" action="/">
                    <p>
                        <label>Name:</label>
                        <input type="text" name="name">
                    </p>
                    <p>
                        <label>Message:</label>
                        <textarea name="message"></textarea>
                    </p>
                    <button type="submit">Submit</button>
                </form>
            </div>
        </section>
        <script>
            function showCongratulations() {{
                alert('Congratulations! You have successfully exploited the vulnerability.');
            }}
        </script>
        <footer>
            <div class="container">
                <p>&copy; 2023 PrimeFit Health Club | All Rights Reserved</p>
            </div>
        </footer>
    </body>
    </html>
    """
    return render_template_string(page)

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)