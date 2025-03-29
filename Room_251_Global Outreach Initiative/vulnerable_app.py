from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

# Home page template
home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Outreach Initiative</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/modern-css-reset/dist/reset.min.css">
    <link href="https://fonts.googleapis.com/css?family=Nunito:400,700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Nunito', sans-serif;
            line-height: 1.6;
            color: #333;
        }
        .header, .footer {
            background: #f4f4f4;
            padding: 20px;
        }
        .header h1, .footer p {
            margin: 0;
        }
        .nav {
            margin: 10px 0;
        }
        .nav a {
            margin-right: 15px;
            color: #0275d8;
            text-decoration: none;
        }
        .hero {
            background: url('https://source.unsplash.com/1600x600/?community,people') no-repeat center center/cover;
            height: 400px;
            position: relative;
            color: #fff;
            text-align: center;
        }
        .hero h2 {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 48px;
            margin: 0;
        }
        .content {
            padding: 20px;
        }
        .content h3 {
            margin-top: 0;
        }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background: #0275d8;
            color: #fff;
            text-decoration: none;
            border-radius: 5px;
        }
        .admin-message {
            background: #dff0d8;
            padding: 20px;
            border: 1px solid #d0e9c6;
            color: #3c763d;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <header class="header">
        <h1>Global Outreach Initiative</h1>
        <nav class="nav">
            <a href="/">Home</a>
            <a href="/about">About Us</a>
            <a href="/projects">Projects</a>
            <a href="/contact">Contact</a>
        </nav>
    </header>
    <section class="hero">
        <h2>Connecting Communities Worldwide</h2>
    </section>
    <section class="content">
        <h3>Our Mission</h3>
        <p>At the Global Outreach Initiative, we aim to empower communities through sustainable projects and cross-cultural collaboration. Join us in making a difference.</p>
        <a href="/donate" class="btn">Donate Now</a>
    </section>
    <footer class="footer">
        <p>&copy; 2023 Global Outreach Initiative. All rights reserved.</p>
    </footer>
</body>
</html>
'''

# Admin page template with congratulations message
admin_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard - Global Outreach Initiative</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/modern-css-reset/dist/reset.min.css">
    <link href="https://fonts.googleapis.com/css?family=Nunito:400,700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Nunito', sans-serif;
            line-height: 1.6;
            color: #333;
            padding: 20px;
        }
        .admin-header {
            margin-bottom: 30px;
        }
        .admin-header h1 {
            margin: 0;
        }
        .admin-content h2 {
            color: #5cb85c;
        }
        .admin-content p {
            font-size: 18px;
        }
        .admin-message {
            background: #dff0d8;
            padding: 20px;
            border: 1px solid #d0e9c6;
            color: #3c763d;
            border-radius: 5px;
            margin-top: 20px;
        }
        .btn-logout {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: #d9534f;
            color: #fff;
            text-decoration: none;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="admin-header">
        <h1>Administrator Dashboard</h1>
    </div>
    <div class="admin-content">
        <h2>Congratulations!</h2>
        <p>You have successfully accessed the admin panel.</p>
        <div class="admin-message">
            <p><strong>Well done!</strong> You have exploited the Improper Access Control vulnerability.</p>
        </div>
        <a href="/" class="btn-logout">Log Out</a>
    </div>
</body>
</html>
'''

# Flask routes
@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/admin')
def admin():
    # Improper Access Control: No authentication implemented
    return render_template_string(admin_page)

# Additional routes for realism
@app.route('/about')
def about():
    return render_template_string('<h2>About Us</h2><p>Information about the organization.</p>')

@app.route('/projects')
def projects():
    return render_template_string('<h2>Our Projects</h2><p>Details of our projects.</p>')

@app.route('/contact')
def contact():
    return render_template_string('<h2>Contact Us</h2><p>Contact information.</p>')

@app.route('/donate')
def donate():
    return render_template_string('<h2>Donate</h2><p>Donation page.</p>')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)