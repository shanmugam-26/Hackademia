from flask import Flask, render_template_string, request, redirect, url_for, session
import hashlib

app = Flask(__name__)
app.secret_key = 'this-should-be-very-secret'

# Simulated database of users
users = {
    'alice': {
        'username': 'alice',
        'password': 'password123',
        'name': 'Alice Johnson',
        'age': 28,
        'posts': [
            "Just had a great day at the park!",
            "Loving the new coffee place downtown."
        ]
    },
    'bob': {
        'username': 'bob',
        'password': 'qwerty456',
        'name': 'Bob Smith',
        'age': 35,
        'posts': [
            "Excited for the concert tonight!",
            "Does anyone have book recommendations?"
        ]
    },
    'charlie': {
        'username': 'charlie',
        'password': 'letmein789',
        'name': 'Charlie Brown',
        'age': 22,
        'posts': [
            "Learning to code in Python is fun!",
            "Just finished reading a great article about cybersecurity."
        ]
    }
}

# HTML templates
login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>SocialSphere - Login</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #eef2f5;}
        .login-container {width: 400px; margin: 100px auto; padding: 30px; background-color: #fff; border-radius: 8px; box-shadow: 0 0 10px #ccc;}
        h2 {text-align: center; color: #333;}
        input[type=text], input[type=password] {width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px;}
        button {width: 100%; padding: 10px; background-color: #5cb85c; color: #fff; border: none; border-radius: 4px;}
        button:hover {background-color: #4cae4c;}
        .error {color: red; text-align: center;}
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Welcome to SocialSphere</h2>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post" action="{{ url_for('login') }}">
            <input type="text" name="username" placeholder="Username" required autofocus>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Log In</button>
        </form>
    </div>
</body>
</html>
'''

profile_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>SocialSphere - {{ user.name }}</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #eef2f5;}
        .profile-container {width: 600px; margin: 50px auto; padding: 30px; background-color: #fff; border-radius: 8px; box-shadow: 0 0 10px #ccc;}
        h2 {color: #333;}
        .logout {float: right;}
        .posts {margin-top: 20px;}
        .post {background-color: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 10px;}
    </style>
</head>
<body>
    <div class="profile-container">
        <div class="logout">
            <a href="{{ url_for('logout') }}">Logout</a>
        </div>
        <h2>{{ user.name }}'s Profile</h2>
        <p><strong>Age:</strong> {{ user.age }}</p>
        <div class="posts">
            <h3>Recent Posts</h3>
            {% for post in user.posts %}
                <div class="post">{{ post }}</div>
            {% endfor %}
        </div>
    </div>
</body>
</html>
'''

admin_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>SocialSphere - Admin Dashboard</title>
    <style>
        body {font-family: Arial, sans-serif; background-color: #eef2f5;}
        .admin-container {width: 600px; margin: 50px auto; padding: 30px; background-color: #fff3cd; border-radius: 8px; box-shadow: 0 0 10px #ccc;}
        h2 {color: #856404;}
        .congrats {background-color: #d4edda; padding: 15px; border-radius: 5px; margin-top: 20px; color: #155724;}
    </style>
</head>
<body>
    <div class="admin-container">
        <h2>Admin Dashboard</h2>
        <p>Welcome to the secret admin panel.</p>
        <div class="congrats">
            <h3>Congratulations!</h3>
            <p>You have successfully exploited the Improper Access Control vulnerability.</p>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('profile', username=session['username']))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and user['password'] == password:
            session['username'] = username
            return redirect(url_for('profile', username=username))
        else:
            error = 'Invalid username or password.'
    return render_template_string(login_template, error=error)

@app.route('/profile')
def profile():
    username = request.args.get('username')
    if not username:
        return redirect(url_for('login'))
    user = users.get(username)
    if user:
        return render_template_string(profile_template, user=user)
    else:
        return "User not found.", 404

@app.route('/admin')
def admin():
    # Improper Access Control Vulnerability: No authentication required to access the admin panel.
    return render_template_string(admin_template)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)