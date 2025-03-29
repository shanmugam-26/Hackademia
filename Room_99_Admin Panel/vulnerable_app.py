from flask import Flask, request, render_template_string, redirect, url_for, make_response
import pickle
import base64

app = Flask(__name__)

class Player:
    def __init__(self, username, score=0, is_admin=False):
        self.username = username
        self.score = score
        self.is_admin = is_admin

@app.route('/')
def index():
    username = request.cookies.get('session')
    if username:
        try:
            player_data = base64.b64decode(username.encode())
            player = pickle.loads(player_data)
            if player.is_admin:
                return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f2f2f2; text-align: center; padding-top:50px;}
        h1 { color: green; }
    </style>
</head>
<body>
    <h1>Congratulations, {{ player.username }}!</h1>
    <p>You have successfully exploited the Insecure Deserialization vulnerability.</p>
</body>
</html>
                ''', player=player)
            else:
                return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Welcome {{ player.username }}</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding-top:50px;}
        h1 { color: #333; }
        a { text-decoration:none; color: blue; }
    </style>
</head>
<body>
    <h1>Welcome back, {{ player.username }}!</h1>
    <p>Your current score is {{ player.score }}.</p>
    <a href="/play">Play a game</a> | <a href="/logout">Logout</a>
</body>
</html>
                ''', player=player)
        except:
            return redirect(url_for('logout'))
    else:
        return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Ultimate Online Gaming Platform</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding-top:50px; }
        a { text-decoration: none; color: blue; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <h1>Welcome to the Ultimate Online Gaming Platform!</h1>
    <p>Please <a href="/login">login</a> to continue.</p>
</body>
</html>
        ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        player = Player(username)
        player_data = pickle.dumps(player)
        player_data_encoded = base64.b64encode(player_data).decode()
        resp = make_response(redirect(url_for('index')))
        resp.set_cookie('session', player_data_encoded)
        return resp
    else:
        return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding-top:50px;}
        input { padding: 10px; margin:5px; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <h1>Login</h1>
    <form method="post">
        <label>Username:</label><br />
        <input type="text" name="username" /><br />
        <input type="submit" value="Login" />
    </form>
</body>
</html>
        ''')

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('session', '', expires=0)
    return resp

@app.route('/play')
def play():
    username = request.cookies.get('session')
    if username:
        try:
            player_data = base64.b64decode(username.encode())
            player = pickle.loads(player_data)
            player.score += 10  # User gains 10 points
            player_data = pickle.dumps(player)
            player_data_encoded = base64.b64encode(player_data).decode()
            resp = make_response(render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Game Result</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding-top:50px;}
        h1 { color: #333; }
        a { text-decoration:none; color: blue; }
    </style>
</head>
<body>
    <h1>Good job, {{ player.username }}!</h1>
    <p>You earned 10 points! Your new score is {{ player.score }}.</p>
    <a href="/">Go back to home</a> | <a href="/logout">Logout</a>
</body>
</html>
            ''', player=player))
            resp.set_cookie('session', player_data_encoded)
            return resp
        except:
            return redirect(url_for('logout'))
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=Fals)