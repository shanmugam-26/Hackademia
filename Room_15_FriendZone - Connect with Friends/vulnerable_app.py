from flask import Flask, render_template_string, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Needed for session management

# Simulated user database
users = {
    'john_doe': 'password123',
}

cover_story = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FriendZone - Connect with Friends</title>
<style>
    body {{
        font-family: Arial, sans-serif;
        background-color: #f0f2f5;
        margin: 0;
    }}
    .header {{
        background-color: #1877f2;
        color: white;
        padding: 15px;
        text-align: center;
    }}
    .login {{
        background-color: white;
        max-width: 400px;
        margin: 50px auto;
        padding: 20px;
        border-radius: 8px;
    }}
    .login h2 {{
        text-align: center;
        color: #1877f2;
    }}
    .login form {{
        display: flex;
        flex-direction: column;
    }}
    .login input[type="text"],
    .login input[type="password"] {{
        padding: 10px;
        margin: 5px 0;
        border: 1px solid #ddd;
        border-radius: 4px;
    }}
    .login input[type="submit"] {{
        padding: 10px;
        background-color: #1877f2;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
    }}
    .login input[type="submit"]:hover {{
        background-color: #145dbf;
    }}
    .footer {{
        text-align: center;
        padding: 20px;
        background-color: #f0f2f5;
        position: fixed;
        width: 100%;
        bottom: 0;
    }}
</style>
</head>
<body>
    <div class="header">
        <h1>FriendZone</h1>
    </div>
    <div class="login">
        <h2>Log In to FriendZone</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Email or Phone Number" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" value="Log In">
        </form>
    </div>
    <div class="footer">
        &copy; 2023 FriendZone
    </div>
</body>
</html>
"""

success_page = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FriendZone - Home</title>
<style>
    body {{
        font-family: Arial, sans-serif;
        background-color: #fff;
        margin: 0;
    }}
    .header {{
        background-color: #1877f2;
        color: white;
        padding: 15px;
        text-align: center;
    }}
    .content {{
        padding: 20px;
    }}
    .welcome {{
        font-size: 24px;
    }}
</style>
</head>
<body>
    <div class="header">
        <h1>FriendZone</h1>
    </div>
    <div class="content">
        <p class="welcome">Welcome, {{username}}!</p>
        <p>You have successfully logged in.</p>
        {congrats}
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Vulnerability: Broken Authentication
        # The authentication mechanism is flawed
        # For demonstration purposes, any password that starts with 'letmein' is accepted

        if username in users and password.startswith('letmein'):
            session['username'] = username
            return redirect(url_for('home', password=password))
        else:
            # Incorrect credentials
            return render_template_string(cover_story)
    return render_template_string(cover_story)

@app.route('/home')
def home():
    if 'username' in session:
        username = session['username']
        
        # Check if the user exploited the vulnerability
        password = request.args.get('password', '')
        congrats = ''
        if password.startswith('letmein'):
            congrats = '<p>Congratulations! You have exploited the Broken Authentication vulnerability.</p>'
        
        return render_template_string(success_page.format(congrats=congrats), username=username)
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)