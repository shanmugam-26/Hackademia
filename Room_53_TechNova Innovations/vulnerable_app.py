from flask import Flask, render_template_string, request, redirect, url_for, make_response
import ssl
import os
import hashlib

app = Flask(__name__)

# In-memory data storage for demonstration purposes
user_data = {
    'admin@technova.com': '5f4dcc3b5aa765d61d8327deb882cf99'  # password: password
}

home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TechNova Innovations</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100">
    <nav class="bg-white shadow">
        <div class="container mx-auto px-6 py-3">
            <div class="flex justify-between items-center">
                <div>
                    <a class="text-gray-800 text-xl font-bold md:text-2xl" href="#">TechNova Innovations</a>
                </div>
                <div class="flex space-x-4">
                    <a class="text-gray-800 hover:text-gray-600" href="#">Home</a>
                    <a class="text-gray-800 hover:text-gray-600" href="#">Products</a>
                    <a class="text-gray-800 hover:text-gray-600" href="#">Contact Us</a>
                </div>
            </div>
        </div>
    </nav>
    <div class="container mx-auto px-6 py-16 text-center">
        <h2 class="text-3xl font-bold mb-2 text-gray-800">Welcome to TechNova Innovations</h2>
        <p class="text-gray-700 mb-8">Innovating the future, one step at a time.</p>
        <form action="/login" method="POST" class="max-w-md mx-auto">
            <div class="mb-4">
                <input class="w-full px-3 py-2 border rounded" type="email" name="email" placeholder="Email Address" required>
            </div>
            <div class="mb-4">
                <input class="w-full px-3 py-2 border rounded" type="password" name="password" placeholder="Password" required>
            </div>
            <div>
                <button class="w-full px-3 py-2 bg-blue-600 text-white rounded" type="submit">Sign In</button>
            </div>
        </form>
    </div>
    <footer class="bg-white">
        <div class="container mx-auto px-6 py-4">
            <p class="text-gray-800">&copy; 2023 TechNova Innovations. All rights reserved.</p>
        </div>
    </footer>
</body>
</html>
'''

congrats_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-green-100">
    <div class="container mx-auto px-6 py-16 text-center">
        <h2 class="text-4xl font-bold mb-2 text-green-800">Congratulations!</h2>
        <p class="text-green-700 mb-8">You have successfully exploited the Insecure Communication vulnerability.</p>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return render_template_string(home_page)

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    # Simulate password hashing (MD5 used here for simplicity, which is insecure)
    password_hash = hashlib.md5(password.encode()).hexdigest()

    # Insecure Communication Vulnerability: Sending sensitive data over HTTP in plain text
    if email in user_data and user_data[email] == password_hash:
        resp = make_response(redirect('http://localhost:8000/dashboard'))
        resp.set_cookie('session_id', '1234567890')  # Insecure session management
        return resp
    else:
        return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET'])
def dashboard():
    session_id = request.cookies.get('session_id')
    if session_id == '1234567890':
        # Sensitive data exposure through insecure communication
        return '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Dashboard</title>
            <!-- Tailwind CSS -->
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-100">
            <div class="container mx-auto px-6 py-16 text-center">
                <h2 class="text-3xl font-bold mb-2 text-gray-800">Welcome, Admin!</h2>
                <p class="text-gray-700 mb-8">This is your dashboard with sensitive information.</p>
            </div>
        </body>
        </html>
        '''
    else:
        return redirect(url_for('index'))

@app.route('/congrats', methods=['GET'])
def congrats():
    return render_template_string(congrats_page)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)