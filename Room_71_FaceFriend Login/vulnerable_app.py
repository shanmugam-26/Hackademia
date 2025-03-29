from flask import Flask, render_template_string, request, redirect, url_for, session
import base64

app = Flask(__name__)
app.secret_key = 'supersecretkey'

@app.route('/')
def index():
    next_url = request.args.get('next', '')
    login_form = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>FaceFriend Login</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f0f2f5; }}
            .login-container {{
                width: 300px;
                margin: 100px auto;
                padding: 30px;
                background-color: #fff;
                box-shadow: 0 2px 4px rgba(0,0,0,0.2);
            }}
            h1 {{ text-align: center; }}
            label {{ display: block; margin-top: 10px; }}
            input[type=text], input[type=password] {{
                width: 100%;
                padding: 10px;
                margin: 5px 0;
                border: 1px solid #ccc;
                box-sizing: border-box;
            }}
            input[type=submit] {{
                background-color: #1877f2;
                color: white;
                padding: 10px;
                border: none;
                width: 100%;
                cursor: pointer;
            }}
            input[type=submit]:hover {{
                background-color: #166fe5;
            }}
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>FaceFriend</h1>
            <form action="/login" method="post">
                <input type="hidden" name="next" value="{next_url}">
                <label for="username">Username:</label>
                <input type="text" name="username" required>
                <label for="password">Password:</label>
                <input type="password" name="password" required>
                <input type="submit" value="Login">
            </form>
        </div>
    </body>
    </html>
    '''
    return render_template_string(login_form, next_url=next_url)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    next_url = request.form.get('next', '')
    if username and password:
        session['username'] = username
        if next_url:
            return redirect(next_url)
        else:
            return redirect(url_for('home'))
    else:
        return redirect(url_for('index'))

@app.route('/home')
def home():
    username = session.get('username', 'User')
    home_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>FaceFriend Home</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f0f2f5; }}
            .header {{ background-color: #fff; padding: 10px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .content {{ padding: 20px; }}
            a {{ color: #1877f2; text-decoration: none; margin: 0 10px; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>FaceFriend</h1>
            <a href="/home">Home</a>
            <a href="/profile">Profile</a>
            <a href="/notifications">Notifications</a>
            <a href="/logout">Logout</a>
        </div>
        <div class="content">
            <h2>Welcome back, {username}!</h2>
            <p>Your feed is currently empty. Start adding friends to see their posts.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(home_page, username=username)

@app.route('/profile')
def profile():
    username = session.get('username', 'User')
    profile_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>FaceFriend Profile</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f0f2f5; }}
            .header {{ background-color: #fff; padding: 10px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .content {{ padding: 20px; }}
            a {{ color: #1877f2; text-decoration: none; margin: 0 10px; }}
            a:hover {{ text-decoration: underline; }}
            .profile-info {{ background-color: #fff; padding: 20px; margin-top: 20px;
                             box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>FaceFriend</h1>
            <a href="/home">Home</a>
            <a href="/profile">Profile</a>
            <a href="/notifications">Notifications</a>
            <a href="/logout">Logout</a>
        </div>
        <div class="content">
            <div class="profile-info">
                <h2>{username}'s Profile</h2>
                <p>Name: {username}</p>
                <p>Bio: Security Enthusiast and Penetration Tester</p>
            </div>
        </div>
    </body>
    </html>
    '''
    return render_template_string(profile_page, username=username)

@app.route('/notifications')
def notifications():
    username = session.get('username', 'User')
    notifications_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>FaceFriend Notifications</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f0f2f5; }}
            .header {{ background-color: #fff; padding: 10px; text-align: center;
                       box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .content {{ padding: 20px; }}
            a {{ color: #1877f2; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            ul {{ list-style-type: none; padding: 0; }}
            li {{ background-color: #fff; margin: 10px 0; padding: 10px;
                  box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>FaceFriend</h1>
            <a href="/home">Home</a>
            <a href="/profile">Profile</a>
            <a href="/notifications">Notifications</a>
            <a href="/logout">Logout</a>
        </div>
        <div class="content">
            <h2>Notifications</h2>
            <ul>
                <li><a href="/go?url={message_url}">You have a new message from Alice</a></li>
                <li><a href="/go?url={event_url}">Event invitation: Security Conference 2023</a></li>
            </ul>
        </div>
    </body>
    </html>
    '''
    message_url = base64.urlsafe_b64encode('/message/1'.encode()).decode()
    event_url = base64.urlsafe_b64encode('/event/123'.encode()).decode()
    return render_template_string(notifications_page, username=username,
                                  message_url=message_url, event_url=event_url)

@app.route('/go')
def go():
    url = request.args.get('url', '')
    try:
        decoded_url = base64.urlsafe_b64decode(url.encode()).decode()
        return redirect(decoded_url)
    except Exception as e:
        return redirect(url_for('home'))

@app.route('/message/1')
def message():
    message_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Message from Alice</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f0f2f5; }}
            .header {{ background-color: #fff; padding: 10px; text-align: center;
                       box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .content {{ padding: 20px; }}
            a {{ color: #1877f2; text-decoration: none; margin: 0 10px; }}
            a:hover {{ text-decoration: underline; }}
            .message {{ background-color: #fff; padding: 20px; margin-top: 20px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>FaceFriend</h1>
            <a href="/home">Home</a>
            <a href="/profile">Profile</a>
            <a href="/notifications">Notifications</a>
            <a href="/logout">Logout</a>
        </div>
        <div class="content">
            <div class="message">
                <h2>Message from Alice</h2>
                <p>Hey, just wanted to check in and see how you're doing!</p>
            </div>
        </div>
    </body>
    </html>
    '''
    return render_template_string(message_page)

@app.route('/event/123')
def event():
    event_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Event Invitation</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f0f2f5; }}
            .header {{ background-color: #fff; padding: 10px; text-align: center;
                       box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .content {{ padding: 20px; }}
            a {{ color: #1877f2; text-decoration: none; margin: 0 10px; }}
            a:hover {{ text-decoration: underline; }}
            .event {{ background-color: #fff; padding: 20px; margin-top: 20px;
                      box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>FaceFriend</h1>
            <a href="/home">Home</a>
            <a href="/profile">Profile</a>
            <a href="/notifications">Notifications</a>
            <a href="/logout">Logout</a>
        </div>
        <div class="content">
            <div class="event">
                <h2>Security Conference 2023</h2>
                <p>You are invited to the annual Security Conference.</p>
            </div>
        </div>
    </body>
    </html>
    '''
    return render_template_string(event_page)

@app.route('/congratulations')
def congratulations():
    congrats_page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Congratulations!</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f0f2f5;
                   text-align: center; padding-top: 100px; }}
            h1 {{ color: #28a745; }}
        </style>
    </head>
    <body>
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the unvalidated redirect vulnerability!</p>
    </body>
    </html>
    '''
    return render_template_string(congrats_page)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=False)