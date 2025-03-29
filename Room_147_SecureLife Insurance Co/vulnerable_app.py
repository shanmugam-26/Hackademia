from flask import Flask, request, send_file, render_template_string
import os

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SecureLife Insurance Co.</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0;}
            .header {background-color: #4CAF50; color: white; padding: 20px; text-align: center;}
            .nav {overflow: hidden; background-color: #333;}
            .nav a {float: left; display: block; color: #f2f2f2; text-align: center;
                    padding: 14px 16px; text-decoration: none;}
            .nav a:hover {background-color: #ddd; color: black;}
            .content {padding: 20px;}
            .footer {background-color: #4CAF50; color: white; text-align: center;
                     padding: 10px; position: fixed; left: 0; bottom: 0; width: 100%;}
            h1 {color: #333;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome to SecureLife Insurance Co.</h1>
            <p>Your partner in securing a better future.</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="/about">About Us</a>
            <a href="/policies">Our Policies</a>
            <a href="/contact">Contact Us</a>
        </div>
        <div class="content">
            <h2>Our Policies</h2>
            <p>Please download our policy documents to know more.</p>
            <ul>
                <li><a href="/download?file=policy1.pdf">Policy Document 1</a></li>
                <li><a href="/download?file=policy2.pdf">Policy Document 2</a></li>
                <li><a href="/download?file=policy3.pdf">Policy Document 3</a></li>
            </ul>
        </div>
        <div class="footer">
            <p>&copy; 2023 SecureLife Insurance Co. All Rights Reserved.</p>
        </div>
    </body>
    </html>
    ''')

@app.route('/download')
def download():
    filename = request.args.get('file')
    # Vulnerable code: Directly using user input without validation
    filepath = os.path.join('files', filename)
    try:
        return send_file(filepath)
    except Exception as e:
        return "File not found!", 404

if __name__ == '__main__':
    if not os.path.exists('files'):
        os.makedirs('files')
        # Create some dummy files
        with open('files/policy1.pdf', 'w') as f:
            f.write('Policy Document 1 Content')
        with open('files/policy2.pdf', 'w') as f:
            f.write('Policy Document 2 Content')
        with open('files/policy3.pdf', 'w') as f:
            f.write('Policy Document 3 Content')
    # Create the congratulations file in the root directory
    with open('congratulations.txt', 'w') as f:
        f.write('Congratulations! You have successfully exploited the Directory Traversal vulnerability.')
    app.run(debug=True)