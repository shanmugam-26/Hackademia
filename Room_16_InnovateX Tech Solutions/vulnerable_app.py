from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    user = request.args.get('user', 'Guest')
    # Vulnerable to XSS due to unsanitized user input
    html_content = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>InnovateX Tech Solutions</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #ffffff; margin: 0; padding: 0; }
            .navbar { background-color: #2c3e50; padding: 15px; text-align: center; color: #ecf0f1; }
            .navbar h1 { margin: 0; }
            .content { padding: 20px; }
            .footer { background-color: #2c3e50; padding: 10px; text-align: center; color: #bdc3c7; position: fixed; bottom: 0; width: 100%; }
            .welcome { font-size: 22px; color: #34495e; }
            .form-container { margin-top: 30px; }
            label { display: block; margin-bottom: 5px; color: #34495e; }
            input[type="text"] { width: 300px; padding: 10px; margin-bottom: 10px; border: 1px solid #bdc3c7; border-radius: 5px; }
            .btn { padding: 10px 20px; background-color: #2980b9; color: #ecf0f1; border: none; border-radius: 5px; cursor: pointer; }
            .btn:hover { background-color: #3498db; }
        </style>
    </head>
    <body>
        <div class="navbar">
            <h1>InnovateX Tech Solutions</h1>
        </div>
        <div class="content">
            <p class="welcome">Welcome, {{ user|safe }}!</p>
            <p>At InnovateX, we pioneer cutting-edge technology to drive innovation forward.</p>
            <div class="form-container">
                <form action="/" method="GET">
                    <label for="user">Enter your username to access exclusive features:</label>
                    <input type="text" id="user" name="user" placeholder="Username">
                    <input type="submit" value="Submit" class="btn">
                </form>
            </div>
        </div>
        <div class="footer">
            &copy; 2023 InnovateX Tech Solutions. All rights reserved.
        </div>
        <script>
            // Hidden congratulatory message for successful XSS exploitation
            if(window.location.hash === '#congrats'){
                alert('Congratulations! You have successfully exploited the XSS vulnerability.');
            }
        </script>
    </body>
    </html>
    '''
    return render_template_string(html_content)

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=False)