from flask import Flask, render_template_string, request, send_from_directory, abort
import os

app = Flask(__name__)

# Simulate a misconfiguration: allow access to a sensitive configuration file
CONFIG_FOLDER = os.path.join(app.root_path, 'config')
app.config['CONFIG_FOLDER'] = CONFIG_FOLDER

# Ensure the 'config' directory exists
if not os.path.exists(CONFIG_FOLDER):
    os.makedirs(CONFIG_FOLDER)

# Create a sensitive configuration file
config_file_path = os.path.join(CONFIG_FOLDER, 'settings.py')
with open(config_file_path, 'w') as f:
    f.write('SECRET_KEY = "SuperSecretKey"\nDEBUG = False\nDATABASE_PASSWORD = "P@ssw0rd!"\n')

@app.route('/')
def index():
    return render_template_string('''
<!doctype html>
<html>
    <head>
        <title>GameZone - The Ultimate Online Gaming Platform</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; background-color: #f0f0f0; }
            h1 { color: #333; margin-top: 50px; }
            p { color: #666; }
            a.button { display: inline-block; margin-top: 20px; padding: 10px 20px; background-color: #007BFF;
                color: #fff; text-decoration: none; border-radius: 5px; }
            a.button:hover { background-color: #0056b3; }
        </style>
    </head>
    <body>
        <h1>Welcome to GameZone!</h1>
        <p>Experience the best online games all in one place.</p>
        <a href="/games" class="button">Browse Games</a>
    </body>
</html>
''')

@app.route('/games')
def games():
    return render_template_string('''
<!doctype html>
<html>
    <head>
        <title>GameZone - Games</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; background-color: #fff; }
            h1 { color: #333; margin-top: 50px; }
            ul { list-style-type: none; padding: 0; }
            li { margin: 10px 0; font-size: 18px; }
            a { color: #007BFF; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>Our Games</h1>
        <ul>
            <li>🌌 Space Adventure</li>
            <li>🧙‍♂️ Fantasy Quest</li>
            <li>🏎️ Racing Pro</li>
        </ul>
        <a href="/">Back to Home</a>
    </body>
</html>
''')

@app.route('/download/<path:filename>')
def download_file(filename):
    # Misconfiguration: allows access to files in the CONFIG_FOLDER
    # In a real application, this should validate and restrict file access properly
    try:
        return send_from_directory(app.config['CONFIG_FOLDER'], filename)
    except Exception:
        abort(404)

@app.errorhandler(403)
def forbidden(e):
    return render_template_string('''
<!doctype html>
<html>
    <head>
        <title>Forbidden</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; background-color: #fff; }
            h1 { color: #e74c3c; margin-top: 50px; }
            p { color: #333; }
            a { color: #007BFF; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>Access Forbidden</h1>
        <p>You don't have permission to access this resource.</p>
        <a href="/">Back to Home</a>
    </body>
</html>
'''), 403

@app.errorhandler(404)
def page_not_found(e):
    return render_template_string('''
<!doctype html>
<html>
    <head>
        <title>Page Not Found</title>
        <style>
            body { font-family: Arial, sans-serif; text-align: center; background-color: #fff; }
            h1 { color: #e74c3c; margin-top: 50px; }
            p { color: #333; }
            a { color: #007BFF; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>Page Not Found</h1>
        <p>The page you are looking for does not exist.</p>
        <a href="/">Back to Home</a>
    </body>
</html>
'''), 404

# Misconfiguration: Expose configuration file via a route
@app.route('/secret-config')
def secret_config():
    # In a real application, configuration files should not be exposed
    # This misconfiguration allows users to view sensitive information
    try:
        with open(config_file_path, 'r') as f:
            content = f.read()
        return render_template_string('''
<!doctype html>
<html>
    <head>
        <title>Secret Configuration</title>
        <style>
            body { font-family: monospace; background-color: #1e1e1e; color: #c5c6c7; padding: 20px; }
            h1 { color: #66fcf1; }
            pre { background-color: #0b0c10; padding: 15px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>Secret Configuration File</h1>
        <pre>{{ content }}</pre>
        <p style="color: #66fcf1;">Congratulations! You have exploited the security misconfiguration vulnerability.</p>
    </body>
</html>
''', content=content)
    except Exception:
        abort(404)

# Uncomment the following lines to run the app
# if __name__ == '__main__':
#     app.run(debug=Fa)