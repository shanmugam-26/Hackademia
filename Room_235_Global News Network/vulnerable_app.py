from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global News Network</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="/">GNN</a>
        <div class="collapse navbar-collapse">
            <ul class="navbar-nav ml-auto">
                <li class="nav-item">
                    <a class="nav-link" href="/exclusive">Exclusive Content</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" href="/login">Log In</a>
                </li>
            </ul>
        </div>
    </nav>
    <div class="container">
        <h1>Welcome to Global News Network</h1>
        <p>Your trusted source for news around the world.</p>
        <div class="row">
            <div class="col-md-4">
                <h3>Breaking News</h3>
                <p>Stay updated with the latest breaking news from around the globe.</p>
            </div>
            <div class="col-md-4">
                <h3>In-Depth Analysis</h3>
                <p>Expert analyses and insights into current events.</p>
            </div>
            <div class="col-md-4">
                <h3>Exclusive Interviews</h3>
                <p>Conversations with leaders, innovators, and newsmakers.</p>
            </div>
        </div>
    </div>
</body>
</html>
''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Authentication logic with a vulnerability
        if username == 'admin' and password == 'secret':
            return redirect(url_for('exclusive', user='admin'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>GNN - Log In</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h2>Log In</h2>
        <form method="post">
            <div class="form-group">
                <label>Username:</label>
                <input class="form-control" type="text" name="username"/>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input class="form-control" type="password" name="password"/>
            </div>
            <p class="text-danger">{{ error }}</p>
            <button class="btn btn-primary" type="submit">Log In</button>
        </form>
    </div>
</body>
</html>
''', error=error)

@app.route('/exclusive')
def exclusive():
    user = request.args.get('user')
    if user == 'admin':
        return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>GNN - Exclusive Content</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h2>Exclusive Content</h2>
        <p>Congratulations! You have accessed the exclusive content.</p>
    </div>
</body>
</html>
''')
    else:
        return redirect(url_for('login'))
if __name__ == '__main__':
        app.run(debug=True)