import os
from flask import Flask, send_file, render_template_string, request

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string('''
        <!doctype html>
        <html>
        <head>
            <title>Global Consulting Group</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f0f0f0; color: #333;}
                header {background-color: #fff; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
                nav a {margin: 0 15px; color: #333; text-decoration: none; font-weight: bold;}
                main {padding: 50px; text-align: center;}
                footer {background-color: #fff; padding: 10px; text-align: center; position: fixed; width: 100%; bottom: 0;}
            </style>
        </head>
        <body>
            <header>
                <h1>Global Consulting Group</h1>
                <nav>
                    <a href="/">Home</a>
                    <a href="/about/">About Us</a>
                    <a href="/services/">Services</a>
                    <a href="/contact/">Contact</a>
                    <a href="/reports/">Reports</a>
                </nav>
            </header>
            <main>
                <h2>Welcome to Global Consulting Group</h2>
                <p>Your success is our business.</p>
            </main>
            <footer>
                &copy; 2023 Global Consulting Group
            </footer>
        </body>
        </html>
    ''')

@app.route('/about/')
def about():
    return render_template_string('''
        <!doctype html>
        <html>
        <head>
            <title>About Us - Global Consulting Group</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f0f0f0; color: #333;}
                header {background-color: #fff; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
                nav a {margin: 0 15px; color: #333; text-decoration: none; font-weight: bold;}
                main {padding: 50px;}
                footer {background-color: #fff; padding: 10px; text-align: center; position: fixed; width: 100%; bottom: 0;}
            </style>
        </head>
        <body>
            <header>
                <h1>Global Consulting Group</h1>
                <nav>
                    <a href="/">Home</a>
                    <a href="/about/">About Us</a>
                    <a href="/services/">Services</a>
                    <a href="/contact/">Contact</a>
                    <a href="/reports/">Reports</a>
                </nav>
            </header>
            <main>
                <h2>About Us</h2>
                <p>We have over 20 years of experience in consulting across various industries...</p>
            </main>
            <footer>
                &copy; 2023 Global Consulting Group
            </footer>
        </body>
        </html>
    ''')

@app.route('/services/')
def services():
    return render_template_string('''
        <!doctype html>
        <html>
        <head>
            <title>Services - Global Consulting Group</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f0f0f0; color: #333;}
                header {background-color: #fff; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
                nav a {margin: 0 15px; color: #333; text-decoration: none; font-weight: bold;}
                main {padding: 50px;}
                footer {background-color: #fff; padding: 10px; text-align: center; position: fixed; width: 100%; bottom: 0;}
            </style>
        </head>
        <body>
            <header>
                <h1>Global Consulting Group</h1>
                <nav>
                    <a href="/">Home</a>
                    <a href="/about/">About Us</a>
                    <a href="/services/">Services</a>
                    <a href="/contact/">Contact</a>
                    <a href="/reports/">Reports</a>
                </nav>
            </header>
            <main>
                <h2>Our Services</h2>
                <p>We offer a wide range of consulting services including strategy, operations, and more.</p>
            </main>
            <footer>
                &copy; 2023 Global Consulting Group
            </footer>
        </body>
        </html>
    ''')

@app.route('/contact/')
def contact():
    return render_template_string('''
        <!doctype html>
        <html>
        <head>
            <title>Contact Us - Global Consulting Group</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f0f0f0; color: #333;}
                header {background-color: #fff; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
                nav a {margin: 0 15px; color: #333; text-decoration: none; font-weight: bold;}
                main {padding: 50px;}
                footer {background-color: #fff; padding: 10px; text-align: center; position: fixed; width: 100%; bottom: 0;}
            </style>
        </head>
        <body>
            <header>
                <h1>Global Consulting Group</h1>
                <nav>
                    <a href="/">Home</a>
                    <a href="/about/">About Us</a>
                    <a href="/services/">Services</a>
                    <a href="/contact/">Contact</a>
                    <a href="/reports/">Reports</a>
                </nav>
            </header>
            <main>
                <h2>Contact Us</h2>
                <p>Feel free to reach out to us for any inquiries.</p>
            </main>
            <footer>
                &copy; 2023 Global Consulting Group
            </footer>
        </body>
        </html>
    ''')

@app.route('/reports/')
def reports_index():
    return render_template_string('''
        <!doctype html>
        <html>
        <head>
            <title>Reports - Global Consulting Group</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f0f0f0; color: #333;}
                header {background-color: #fff; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
                nav a {margin: 0 15px; color: #333; text-decoration: none; font-weight: bold;}
                main {padding: 50px;}
                footer {background-color: #fff; padding: 10px; text-align: center; position: fixed; width: 100%; bottom: 0;}
                ul {list-style-type: none;}
                li {margin: 10px 0;}
                a {color: #1a0dab;}
            </style>
        </head>
        <body>
            <header>
                <h1>Global Consulting Group</h1>
                <nav>
                    <a href="/">Home</a>
                    <a href="/about/">About Us</a>
                    <a href="/services/">Services</a>
                    <a href="/contact/">Contact</a>
                    <a href="/reports/">Reports</a>
                </nav>
            </header>
            <main>
                <h2>Reports</h2>
                <ul>
                    <li><a href="/reports/2023-q3-report.pdf">2023 Q3 Report</a></li>
                    <li><a href="/reports/2023-q2-report.pdf">2023 Q2 Report</a></li>
                    <li><a href="/reports/2023-q1-report.pdf">2023 Q1 Report</a></li>
                </ul>
            </main>
            <footer>
                &copy; 2023 Global Consulting Group
            </footer>
        </body>
        </html>
    ''')

@app.route('/reports/<path:filename>')
def reports(filename):
    return send_file('reports/' + filename)

if __name__ == '__main__':
    # Ensure the reports directory exists
    if not os.path.exists('reports'):
        os.makedirs('reports')
    # Create dummy report files
    for report_name in ['2023-q3-report.pdf', '2023-q2-report.pdf', '2023-q1-report.pdf']:
        report_path = os.path.join('reports', report_name)
        if not os.path.exists(report_path):
            with open(report_path, 'w') as f:
                f.write(f'Dummy content for {report_name}')
    # Create the secret file
    with open('secret.txt', 'w') as f:
        f.write('Congratulations, you found the secret!')
    app.run(debug=True, port=5000)