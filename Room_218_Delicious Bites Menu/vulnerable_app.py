from flask import Flask, render_template_string, request, send_file, abort
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Set up the necessary directories and files
files_dir = os.path.join(BASE_DIR, 'files')
if not os.path.exists(files_dir):
    os.makedirs(files_dir)

# Create menu.html if it doesn't exist
menu_html_path = os.path.join(files_dir, 'menu.html')
if not os.path.exists(menu_html_path):
    with open(menu_html_path, 'w') as f:
        f.write('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Delicious Bites Menu</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container">
        <h1>Our Menu</h1>
        <p>Here are some of our delicious offerings!</p>
        <!-- Add menu items here -->
    </div>
</body>
</html>
''')

# Create secret.txt
secret_txt_path = os.path.join(BASE_DIR, 'secret.txt')
if not os.path.exists(secret_txt_path):
    with open(secret_txt_path, 'w') as f:
        f.write('Congratulations, you have found the secret message!')

@app.route('/')
def home():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Delicious Bites Restaurant</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css">
     <!-- Include other necessary CSS and JS libraries -->
</head>
<body>
    <div class="container">
        <h1 class="mt-5">Welcome to Delicious Bites</h1>
        <p>Experience the best gourmet food in town!</p>
        <p>Check out our <a href="/menu?item=menu.html">menu</a> for today.</p>
    </div>
</body>
</html>
''')

@app.route('/menu')
def menu():
    item = request.args.get('item', '')
    filepath = os.path.join(BASE_DIR, 'files', item)
    try:
        return send_file(filepath)
    except Exception:
        abort(404)

@app.errorhandler(404)
def page_not_found(e):
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Delicious Bites - 404 Not Found</title>
</head>
<body>
    <div class="container">
        <h1>Oops! That page doesn't exist.</h1>
        <p>Return to <a href="/">home page</a>.</p>
    </div>
</body>
</html>
'''), 404
if __name__ == '__main__':
        app.run(debug=True)