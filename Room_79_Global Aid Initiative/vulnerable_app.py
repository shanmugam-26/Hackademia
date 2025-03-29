from flask import Flask, render_template_string, request, send_file, abort
import os

app = Flask(__name__)

# Home page
@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global Aid Initiative</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #eef; margin: 0; }
            .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
            .nav { overflow: hidden; background-color: #333; }
            .nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                     padding: 14px 16px; text-decoration: none; }
            .nav a:hover { background-color: #ddd; color: black; }
            .content { padding: 20px; }
            .footer { background-color: #2c3e50; color: white; text-align: center; padding: 10px;
                      position: fixed; bottom: 0; width: 100%; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Global Aid Initiative</h1>
            <p>Empowering communities worldwide.</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/documents">Publications</a>
            <a href="/contact">Contact Us</a>
        </div>
        <div class="content">
            <h2>Welcome to Global Aid Initiative</h2>
            <p>Our mission is to provide support and resources to underprivileged communities around the globe.</p>
            <p>Explore our publications to learn more about our efforts and impact.</p>
        </div>
        <div class="footer">
            <p>&copy; 2023 Global Aid Initiative</p>
        </div>
    </body>
    </html>
    ''')

# Documents page
@app.route('/documents')
def documents():
    files = os.listdir('documents')
    files = [f for f in files if os.path.isfile(os.path.join('documents', f))]
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Publications - Global Aid Initiative</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #eef; margin: 0; }
            .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
            .nav { overflow: hidden; background-color: #333; }
            .nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                     padding: 14px 16px; text-decoration: none; }
            .nav a:hover { background-color: #ddd; color: black; }
            .content { padding: 20px; }
            .footer { background-color: #2c3e50; color: white; text-align: center; padding: 10px;
                      position: fixed; bottom: 0; width: 100%; }
            ul { list-style-type: none; padding: 0; }
            li { background-color: #fff; margin: 5px 0; padding: 10px; }
            a { color: #2c3e50; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Our Publications</h1>
            <p>Insights and reports from our recent activities.</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/documents">Publications</a>
            <a href="/contact">Contact Us</a>
        </div>
        <div class="content">
            <h2>Available Documents</h2>
            <ul>
                {% for file in files %}
                    <li><a href="/view?file={{ file }}">{{ file }}</a></li>
                {% endfor %}
            </ul>
        </div>
        <div class="footer">
            <p>&copy; 2023 Global Aid Initiative</p>
        </div>
    </body>
    </html>
    ''', files=files)

# Vulnerable view route
@app.route('/view')
def view():
    filename = request.args.get('file', '')
    filepath = os.path.join('documents', filename)
    if os.path.exists(filepath):
        return send_file(filepath)
    else:
        return abort(404)

# Contact page
@app.route('/contact')
def contact():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Contact Us - Global Aid Initiative</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #eef; margin: 0; }
            .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
            .nav { overflow: hidden; background-color: #333; }
            .nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                     padding: 14px 16px; text-decoration: none; }
            .nav a:hover { background-color: #ddd; color: black; }
            .content { padding: 20px; }
            .footer { background-color: #2c3e50; color: white; text-align: center; padding: 10px;
                      position: fixed; bottom: 0; width: 100%; }
            form { max-width: 600px; margin: auto; }
            input[type=text], textarea { width: 100%; padding: 12px; border: 1px solid #ccc;
                                         border-radius: 4px; margin-top: 6px; margin-bottom: 16px; resize: vertical; }
            input[type=submit] { background-color: #2c3e50; color: white; padding: 12px 20px;
                                 border: none; border-radius: 4px; cursor: pointer; }
            input[type=submit]:hover { background-color: #45a049; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Contact Us</h1>
            <p>We value your feedback and inquiries.</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/documents">Publications</a>
            <a href="/contact">Contact Us</a>
        </div>
        <div class="content">
            <h2>Get in Touch</h2>
            <p>Email: info@globalaid.org</p>
            <p>Phone: +1 (555) 123-4567</p>
            <p>Address: 100 International Way, Unity City, Earth</p>
        </div>
        <div class="footer">
            <p>&copy; 2023 Global Aid Initiative</p>
        </div>
    </body>
    </html>
    ''')

# Run the application
if __name__ == '__main__':
    if not os.path.exists('documents'):
        os.makedirs('documents')
    app.run(debug=True)