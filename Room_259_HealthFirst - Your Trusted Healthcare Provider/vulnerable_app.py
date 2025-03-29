from flask import Flask, render_template_string, request, make_response
import pickle
import base64

app = Flask(__name__)

main_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>HealthFirst - Your Trusted Healthcare Provider</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>

<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="/">HealthFirst</a>
    </nav>

    <div class="container">
        <h1 class="mt-5">Welcome to HealthFirst Portal</h1>
        <p>Your health is our priority.</p>

        <div class="mt-4">
            <h3>Your Preferences</h3>
            <p>{{ preferences }}</p>
        </div>
    </div>
</body>

</html>
'''

exploit_succeeded = False

def set_exploit_succeeded():
    global exploit_succeeded
    exploit_succeeded = True
    return "Exploit executed"

class UserPreferences:
    def __init__(self, data):
        self.data = data

class Exploit(object):
    def __reduce__(self):
        return (set_exploit_succeeded, ())

@app.route('/')
def index():
    global exploit_succeeded
    preferences = "No preferences set."
    prefs_cookie = request.cookies.get('prefs')
    if prefs_cookie:
        try:
            prefs_bytes = base64.b64decode(prefs_cookie)
            prefs = pickle.loads(prefs_bytes)
            if exploit_succeeded:
                preferences = "Congratulations! You've successfully exploited the vulnerability."
                exploit_succeeded = False  # Reset for next time
            elif isinstance(prefs, UserPreferences):
                preferences = prefs.data
            else:
                preferences = "Error loading preferences."
        except Exception as e:
            preferences = "Error loading preferences."
        resp = make_response(render_template_string(main_page_html, preferences=preferences))
    else:
        # Set default preferences
        prefs = UserPreferences('Default preference')
        prefs_bytes = pickle.dumps(prefs)
        prefs_b64 = base64.b64encode(prefs_bytes).decode('utf-8')
        resp = make_response(render_template_string(main_page_html, preferences=prefs.data))
        resp.set_cookie('prefs', prefs_b64)

    return resp

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)