from flask import Flask, render_template_string, request, Response

app = Flask(__name__)

@app.route('/')
def index():
    # Render the main page
    return render_template_string('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FitLife Fitness Center</title>
    <style>
        /* CSS styles here for attractiveness */
        body {font-family: Arial, sans-serif; margin: 0; padding: 0;}
        header {background-color: #333; color: #fff; padding: 20px; text-align: center;}
        nav {background-color: #444; overflow: hidden;}
        nav a {float: left; display: block; color: #fff; text-align: center; padding: 14px 16px; text-decoration: none;}
        nav a:hover {background-color: #ddd; color: black;}
        main {padding: 20px;}
        footer {background-color: #333; color: #fff; padding: 10px; text-align: center;}
    </style>
    <script src="/static/main.js"></script>
</head>
<body>
    <header>
        <h1>Welcome to FitLife Fitness Center</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="#">Programs</a>
        <a href="#">Membership</a>
        <a href="#">Contact Us</a>
    </nav>
    <main>
        <h2>Login to your account</h2>
        <form action="/login" method="post">
            <label>Username: <input type="text" name="username"/></label><br/>
            <label>Password: <input type="password" name="password"/></label><br/>
            <input type="submit" value="Login"/>
        </form>
    </main>
    <footer>
        &copy; 2023 FitLife Fitness Center
    </footer>
</body>
</html>
''')

@app.route('/login', methods=['POST'])
def login():
    # Just return invalid credentials for any login attempt
    return 'Invalid credentials'

@app.route('/static/main.js')
def main_js():
    # Return the JavaScript code
    js_code = '''
console.log("Welcome to FitLife Fitness Center!");

// var apiKey = atob("MTIzNDUtU0VDUkVULUFQSS1LRVk="); // TODO: Remove this before deployment

function init() {
    // Initialization code
}

init();
'''
    return Response(js_code, mimetype='application/javascript')

@app.route('/api/admin_data')
def admin_data():
    api_key = request.args.get('api_key')
    if api_key == "12345-SECRET-API-KEY":
        sensitive_data = '''Congratulations! You've found the sensitive data!
Admin credentials:
Username: admin
Password: SuperSecretPassword123
'''
        return sensitive_data
    else:
        return 'Access denied'

if __name__ == '__main__':
    app.run(debug=False)