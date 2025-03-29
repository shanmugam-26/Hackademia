from flask import Flask, request, render_template_string, redirect, url_for
import requests

app = Flask(__name__)

home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>HealthFirst Medical Center</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f8ff; }
        header { background-color: #008080; color: white; padding: 20px; text-align: center; }
        nav { margin: 0; padding: 10px; background-color: #20b2aa; text-align: center; }
        nav a { margin: 10px; color: white; text-decoration: none; font-weight: bold; }
        section { padding: 20px; }
        footer { background-color: #008080; color: white; padding: 10px; text-align: center; }
    </style>
</head>
<body>
    <header>
        <h1>Welcome to HealthFirst Medical Center</h1>
    </header>
    <nav>
        <a href="{{ url_for('home') }}">Home</a>
        <a href="{{ url_for('resources') }}">Patient Resources</a>
    </nav>
    <section>
        <h2>About Us</h2>
        <p>At HealthFirst Medical Center, we are committed to providing top-notch healthcare services to our community.</p>
    </section>
    <footer>
        &copy; 2023 HealthFirst Medical Center
    </footer>
</body>
</html>
'''

resources_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Patient Resources - HealthFirst Medical Center</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f8ff; }
        header { background-color: #008080; color: white; padding: 20px; text-align: center; }
        nav { margin: 0; padding: 10px; background-color: #20b2aa; text-align: center; }
        nav a { margin: 10px; color: white; text-decoration: none; font-weight: bold; }
        section { padding: 20px; }
        footer { background-color: #008080; color: white; padding: 10px; text-align: center; }
        form { margin-top: 20px; }
        input[type="text"] { width: 80%; padding: 10px; }
        input[type="submit"] { padding: 10px 20px; }
    </style>
</head>
<body>
    <header>
        <h1>Patient Resources</h1>
    </header>
    <nav>
        <a href="{{ url_for('home') }}">Home</a>
        <a href="{{ url_for('resources') }}">Patient Resources</a>
    </nav>
    <section>
        <h2>Access Educational Materials</h2>
        <p>Enter the URL of the resource you wish to view:</p>
        <form method="post">
            <input type="text" name="url" placeholder="https://example.com/resource.pdf" required/>
            <input type="submit" value="Fetch Resource"/>
        </form>
    </section>
    <footer>
        &copy; 2023 HealthFirst Medical Center
    </footer>
</body>
</html>
'''

resource_result_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Resource Content - HealthFirst Medical Center</title>
    <style>
        body { font-family: Courier New, monospace; background-color: #f0f8ff; }
        pre { background-color: #fff; padding: 20px; overflow: auto; }
        header { background-color: #008080; color: white; padding: 20px; text-align: center; }
        nav { margin: 0; padding: 10px; background-color: #20b2aa; text-align: center; }
        nav a { margin: 10px; color: white; text-decoration: none; font-weight: bold; }
        section { padding: 20px; }
        footer { background-color: #008080; color: white; padding: 10px; text-align: center; }
        .content { white-space: pre-wrap; word-wrap: break-word; background-color: #fff; padding: 20px; border: 1px solid #ccc; }
    </style>
</head>
<body>
    <header>
        <h1>Resource Content</h1>
    </header>
    <nav>
        <a href="{{ url_for('home') }}">Home</a>
        <a href="{{ url_for('resources') }}">Patient Resources</a>
    </nav>
    <section>
        <div class="content">
        {{ content | safe }}
        </div>
    </section>
    <footer>
        &copy; 2023 HealthFirst Medical Center
    </footer>
</body>
</html>
'''

admin_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Panel - HealthFirst Medical Center</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fff0f5; }
        header { background-color: #8b0000; color: white; padding: 20px; text-align: center; }
        section { padding: 20px; }
        h2 { color: #8b0000; }
        p { font-size: 1.2em; }
    </style>
</head>
<body>
    <header>
        <h1>Admin Panel</h1>
    </header>
    <section>
        <h2>Congratulations!</h2>
        <p>You have successfully exploited the SSRF vulnerability.</p>
        <p><strong>Flag: FLAG{SSRF_Vulnerability_Exploited}</strong></p>
    </section>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/resources', methods=['GET', 'POST'])
def resources():
    if request.method == 'POST':
        resource_url = request.form.get('url')
        try:
            # SSRF vulnerability: fetching user-provided URL without validation
            resp = requests.get(resource_url)
            content = resp.text
        except Exception as e:
            content = f"<p>Error fetching resource: {e}</p>"
        return render_template_string(resource_result_page, content=content)
    return render_template_string(resources_page)

@app.route('/admin')
def admin():
    # Simulate internal-only access by blocking direct external requests
    client_ip = request.remote_addr
    if client_ip != '127.0.0.1':
        return "Access denied", 403
    return render_template_string(admin_page)

if __name__ == '__main__':
    app.run(debug=True)