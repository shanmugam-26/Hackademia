from flask import Flask, request, redirect, url_for, make_response, render_template_string
import hashlib
import random
import string

app = Flask(__name__)

# Simulated database of users
users = {
    'alice': hashlib.sha256('password123'.encode()).hexdigest(),
    'bob': hashlib.sha256('securepassword'.encode()).hexdigest()
}

# Sessions stored with session_id as key
sessions = {}

login_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>HealthPlus Provider Login</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
        }}
        .container {{
            width: 400px;
            margin: 0 auto;
            margin-top: 100px;
            padding: 20px;
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h2 {{
            text-align: center;
            color: #4CAF50;
        }}
        input[type=text], input[type=password] {{
            width: 100%;
            padding: 12px 20px;
            margin: 8px 0;
            display: inline-block;
            border: 1px solid #ccc;
            box-sizing: border-box;
        }}
        button {{
            background-color: #4CAF50;
            color: white;
            padding: 14px 20px;
            margin: 8px 0;
            border: none;
            cursor: pointer;
            width: 100%;
        }}
        .error {{
            color: red;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>HealthPlus Provider Portal</h2>
        {% if error %}
            <p class="error">{{{{ error }}}}</p>
        {% endif %}
        <form method="post">
            <label for="username"><b>Username</b></label>
            <input type="text" placeholder="Enter Username" name="username" required>
            <label for="password"><b>Password</b></label>
            <input type="password" placeholder="Enter Password" name="password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
'''

home_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>HealthPlus Provider Dashboard</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
        }}
        .container {{
            width: 800px;
            margin: 0 auto;
            margin-top: 50px;
        }}
        h2 {{
            color: #4CAF50;
        }}
        .welcome {{
            margin-bottom: 20px;
        }}
        .card {{
            background-color: #fff;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 0 5px rgba(0,0,0,0.1);
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Provider Dashboard</h2>
        <div class="welcome">
            <p>Welcome, {{{{ username }}}}!</p>
        </div>
        <div class="card">
            <h3>Patient Appointments</h3>
            <p>No upcoming appointments.</p>
        </div>
        <div class="card">
            <h3>Messages</h3>
            <p>You have no new messages.</p>
        </div>
    </div>
</body>
</html>
'''

congrats_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>HealthPlus Admin Panel</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f0fff0;
        }}
        .container {{
            width: 600px;
            margin: 0 auto;
            margin-top: 100px;
            text-align: center;
        }}
        h2 {{
            color: #4CAF50;
        }}
        p {{
            font-size: 18px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h2>Congratulations!</h2>
        <p>You have successfully exploited the Session Fixation vulnerability as {{{{ username }}}}.</p>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def login():
    session_id = request.cookies.get('session_id')
    if not session_id:
        # Generate a new session id
        session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        resp = make_response(redirect(url_for('login')))
        resp.set_cookie('session_id', session_id)
        return resp
    else:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')

            if username in users:
                hashed_pw = hashlib.sha256(password.encode()).hexdigest()
                if users[username] == hashed_pw:
                    # Save the username in the session
                    sessions[session_id] = username
                    return redirect(url_for('home'))
            error = 'Invalid username or password'
            return render_template_string(login_template, error=error)
        else:
            return render_template_string(login_template, error=None)

@app.route('/home')
def home():
    session_id = request.cookies.get('session_id')
    if session_id in sessions:
        username = sessions[session_id]
        return render_template_string(home_template, username=username)
    else:
        return redirect(url_for('login'))

@app.route('/set_session')
def set_session():
    session_id = request.args.get('session_id')
    if session_id:
        resp = make_response(redirect(url_for('login')))
        resp.set_cookie('session_id', session_id)
        return resp
    else:
        return redirect(url_for('login'))

@app.route('/admin')
def admin():
    session_id = request.cookies.get('session_id')
    if session_id in sessions:
        username = sessions[session_id]
        if username:
            return render_template_string(congrats_template, username=username)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)