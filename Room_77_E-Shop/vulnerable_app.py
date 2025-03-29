from flask import Flask, request, redirect, render_template_string, make_response

app = Flask(__name__)
app.secret_key = 'supersecretkey'

users = {
    'user1': 'password1',
    'user2': 'password2',
    'admin': 'supersecret'
}

@app.route('/')
def index():
    username = None
    if 'session' in request.cookies:
        import base64
        try:
            username = base64.b64decode(request.cookies.get('session')).decode('utf-8')
        except:
            pass
    template = '''
    <html>
        <head>
            <title>E-Shop</title>
            <style>
                body { font-family: Arial, sans-serif; }
                h1 { color: #333; }
                nav { margin-bottom: 20px; }
                nav a { margin-right: 10px; text-decoration: none; color: #555; }
                .products { display: flex; }
                .product { border: 1px solid #ddd; padding: 10px; margin-right: 10px; }
                .product img { max-width: 100px; }
            </style>
        </head>
        <body>
            <nav>
                <a href="/">Home</a>
                {% if username %}
                    <a href="/profile">Profile</a>
                    <a href="/logout">Logout</a>
                {% else %}
                    <a href="/login">Login</a>
                {% endif %}
            </nav>
            <h1>Welcome to E-Shop</h1>
            {% if username %}
                <p>Hello, {{ username }}!</p>
                {% if username == 'admin' %}
                    <p><a href="/admin">Admin Panel</a></p>
                {% endif %}
            {% endif %}
            <h2>Our Products</h2>
            <div class="products">
                <div class="product">
                    <img src="https://via.placeholder.com/100" alt="Product 1"/>
                    <p>Product 1 - $10</p>
                </div>
                <div class="product">
                    <img src="https://via.placeholder.com/100" alt="Product 2"/>
                    <p>Product 2 - $20</p>
                </div>
                <div class="product">
                    <img src="https://via.placeholder.com/100" alt="Product 3"/>
                    <p>Product 3 - $30</p>
                </div>
            </div>
        </body>
    </html>
    '''
    return render_template_string(template, username=username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            import base64
            resp = make_response(redirect('/'))
            session_token = base64.b64encode(username.encode('utf-8')).decode('utf-8')
            resp.set_cookie('session', session_token)
            return resp
        else:
            template = '''
            <html>
                <head>
                    <title>E-Shop Login</title>
                    <style>
                        body { font-family: Arial, sans-serif; }
                        .error { color: red; }
                    </style>
                </head>
                <body>
                    <h1>Login</h1>
                    <p class="error">Invalid credentials. Please try again.</p>
                    <form action="/login" method="post">
                        <label>Username:</label><br/>
                        <input type="text" name="username"/><br/>
                        <label>Password:</label><br/>
                        <input type="password" name="password"/><br/>
                        <input type="submit" value="Login"/>
                    </form>
                </body>
            </html>
            '''
            return render_template_string(template)
    else:
        template = '''
        <html>
            <head>
                <title>E-Shop Login</title>
                <style>
                    body { font-family: Arial, sans-serif; }
                    h1 { color: #333; }
                    form { max-width: 300px; margin: auto; }
                    input[type=text], input[type=password] { width: 100%; padding: 12px; margin: 8px 0; }
                    input[type=submit] { background-color: #4CAF50; color: white; padding: 12px; border: none; cursor: pointer; width: 100%; }
                </style>
            </head>
            <body>
                <h1>Login</h1>
                <form action="/login" method="post">
                    <label>Username:</label><br/>
                    <input type="text" name="username"/><br/>
                    <label>Password:</label><br/>
                    <input type="password" name="password"/><br/>
                    <input type="submit" value="Login"/>
                </form>
            </body>
        </html>
        '''
        return render_template_string(template)

@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.delete_cookie('session')
    return resp

@app.route('/profile')
def profile():
    username = None
    if 'session' in request.cookies:
        import base64
        try:
            username = base64.b64decode(request.cookies.get('session')).decode('utf-8')
        except:
            pass
    if username:
        template = '''
        <html>
            <head>
                <title>{{ username }}'s Profile</title>
                <style>
                    body { font-family: Arial, sans-serif; }
                    h1 { color: #333; }
                </style>
            </head>
            <body>
                <nav>
                    <a href="/">Home</a>
                    <a href="/logout">Logout</a>
                </nav>
                <h1>Welcome, {{ username }}</h1>
                <p>This is your profile page.</p>
            </body>
        </html>
        '''
        return render_template_string(template, username=username)
    else:
        return redirect('/login')

@app.route('/admin')
def admin():
    username = None
    if 'session' in request.cookies:
        import base64
        try:
            username = base64.b64decode(request.cookies.get('session')).decode('utf-8')
        except:
            pass
    if username == 'admin':
        template = '''
        <html>
            <head>
                <title>Admin Panel</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #333; color: #fff; }
                    h1 { color: #fff; }
                </style>
            </head>
            <body>
                <h1>Admin Panel</h1>
                <p>Congratulations! You have successfully exploited the vulnerability.</p>
                <p><a href="/" style="color: #4CAF50;">Home</a></p>
            </body>
        </html>
        '''
        return render_template_string(template)
    else:
        return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)