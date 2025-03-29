from flask import Flask, render_template_string, request, redirect, url_for, session
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Sample user data (In a real app, this would come from a database)
users = {
    'john_doe': {
        'name': 'John Doe',
        'password': 'password123',  # Weak password stored in plaintext
        'email': 'john@example.com',
        'ssn': '123-45-6789',       # Sensitive Information
    }
}

# Templates
login_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Socialize - Login</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/milligram/1.4.1/milligram.min.css">
</head>
<body>
    <div class="container">
        <h2>Welcome to Socialize</h2>
        <form action="/login" method="post">
            <label for="username">Username:</label>
            <input type="text" name="username" required>
            <label for="password">Password:</label>
            <input type="password" name="password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
'''

profile_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Socialize - Profile</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/milligram/1.4.1/milligram.min.css">
</head>
<body>
    <div class="container">
        <h2>Hello, {{ name }}</h2>
        <p>Email: {{ email }}</p>
        <p>SSN: {{ ssn }}</p>
        <a href="/logout">Logout</a>
    </div>
</body>
</html>
'''

congrats_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/milligram/1.4.1/milligram.min.css">
</head>
<body>
    <div class="container">
        <h2>Congratulations!</h2>
        <p>You have successfully exploited the Sensitive Data Exposure vulnerability.</p>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(login_page)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = users.get(username)
    if user and user['password'] == password:
        session['username'] = username
        return redirect(url_for('profile'))
    else:
        return redirect(url_for('index'))

@app.route('/profile')
def profile():
    username = session.get('username')
    if username:
        user = users.get(username)
        return render_template_string(profile_page, name=user['name'], email=user['email'], ssn=user['ssn'])
    else:
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/congrats')
def congrats():
    return render_template_string(congrats_page)
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)