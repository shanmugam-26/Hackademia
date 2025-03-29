from flask import Flask, request, render_template_string, make_response
import base64
import pickle

app = Flask(__name__)

# Main page template using Bootstrap
main_page_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>HealthSure - Your Trusted Healthcare Partner</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <div class="jumbotron text-center mt-5">
        <h1>Welcome to HealthSure</h1>
        <p>Your health, our priority.</p>
    </div>
    <div class="row">
        <div class="col-md-12">
            <p>At HealthSure, we are committed to providing the best healthcare services to our patients. Our team of dedicated professionals works around the clock to ensure you receive the care you deserve.</p>
            <p>Access your personalized dashboard to view your health records, upcoming appointments, and more.</p>
            <form method="post" action="/login">
                <button type="submit" class="btn btn-primary">Access My Dashboard</button>
            </form>
        </div>
    </div>
</div>
</body>
</html>
'''

# Congratulations page template
congrats_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
<div class="container text-center mt-5">
    <div class="jumbotron">
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the Insecure Deserialization vulnerability.</p>
        <p>Your skills are exceptional!</p>
    </div>
</div>
</body>
</html>
'''

# User class
class User(object):
    def __init__(self, username):
        self.username = username

@app.route('/')
def index():
    session_cookie = request.cookies.get('session')
    if session_cookie:
        try:
            # Decode the session cookie
            session_data = base64.b64decode(session_cookie)
            # Insecure deserialization vulnerability
            user = pickle.loads(session_data)
            if user.username == 'admin':
                # User has escalated privileges
                return render_template_string(congrats_template)
            else:
                return render_template_string(main_page_template)
        except Exception as e:
            # On error, render the main page
            return render_template_string(main_page_template)
    else:
        return render_template_string(main_page_template)

@app.route('/login', methods=['POST'])
def login():
    # Create a user object for the session
    user = User('guest')
    # Serialize the user object
    session_data = pickle.dumps(user)
    # Encode the serialized object
    session_cookie = base64.b64encode(session_data).decode('utf-8')
    resp = make_response(render_template_string(main_page_template))
    # Set the session cookie
    resp.set_cookie('session', session_cookie)
    return resp
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)