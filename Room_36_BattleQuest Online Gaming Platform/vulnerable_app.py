from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

# Simulated database of users
users = {
    1: {'username': 'player1', 'highscore': 1500},
    2: {'username': 'player2', 'highscore': 2000},
    3: {'username': 'player3', 'highscore': 1800},
    999: {'username': 'admin', 'highscore': 9999, 'congrats': True}
}

@app.route('/')
def index():
    # The home page with a welcome message
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>BattleQuest Online Gaming Platform</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #1e1e1e;
                    color: #ffffff;
                    text-align: center;
                    padding-top: 50px;
                }
                a {
                    color: #00ff00;
                    text-decoration: none;
                    font-size: 20px;
                }
                a:hover {
                    color: #ff0000;
                }
            </style>
        </head>
        <body>
            <h1>Welcome to <span style="color:#00ff00;">BattleQuest</span>!</h1>
            <p>Experience the ultimate online gaming adventure.</p>
            <a href="/login">Login to your profile</a>
        </body>
        </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_id = int(request.form['user_id'])
        return redirect(url_for('profile', id=user_id))
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>BattleQuest Login</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #1e1e1e;
                    color: #ffffff;
                    text-align: center;
                    padding-top: 50px;
                }
                input[type=text] {
                    padding: 10px;
                    font-size: 16px;
                }
                input[type=submit] {
                    padding: 10px 20px;
                    font-size: 16px;
                    background-color: #00ff00;
                    color: #1e1e1e;
                    border: none;
                    cursor: pointer;
                }
                input[type=submit]:hover {
                    background-color: #ff0000;
                    color: #ffffff;
                }
            </style>
        </head>
        <body>
            <h1>Login to <span style="color:#00ff00;">BattleQuest</span></h1>
            <form method="post">
                <label for="user_id">User ID:</label><br><br>
                <input type="text" name="user_id" id="user_id"><br><br>
                <input type="submit" value="Login">
            </form>
        </body>
        </html>
    ''')

@app.route('/profile')
def profile():
    user_id = int(request.args.get('id'))
    user = users.get(user_id)
    if user:
        if user.get('congrats'):
            # Display the congratulations message
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Congratulations!</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            background-color: #1e1e1e;
                            color: #00ff00;
                            text-align: center;
                            padding-top: 50px;
                        }
                    </style>
                </head>
                <body>
                    <h1>Congratulations!</h1>
                    <p>You have found the secret admin profile!</p>
                    <p>Your elite skills have unlocked hidden content.</p>
                </body>
                </html>
            ''')
        else:
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>{{ username }}'s Profile</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            background-color: #1e1e1e;
                            color: #ffffff;
                            text-align: center;
                            padding-top: 50px;
                        }
                        a {
                            color: #00ff00;
                            text-decoration: none;
                            font-size: 20px;
                        }
                        a:hover {
                            color: #ff0000;
                        }
                    </style>
                </head>
                <body>
                    <h1>Welcome, {{ username }}!</h1>
                    <p>Your high score: <strong>{{ highscore }}</strong></p>
                    <p><a href="/">Back to home</a></p>
                </body>
                </html>
            ''', username=user['username'], highscore=user['highscore'])
    else:
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Error</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #1e1e1e;
                        color: #ffffff;
                        text-align: center;
                        padding-top: 50px;
                    }
                    a {
                        color: #00ff00;
                        text-decoration: none;
                        font-size: 20px;
                    }
                    a:hover {
                        color: #ff0000;
                    }
                </style>
            </head>
            <body>
                <h1>User not found!</h1>
                <p>The user ID you provided does not exist.</p>
                <p><a href="/">Back to home</a></p>
            </body>
            </html>
        ''')

if __name__ == '__main__':
    app.run(debug=False)