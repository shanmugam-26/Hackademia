from flask import Flask, render_template_string, request
import os

SECRET_MESSAGE = "Congratulations! You have successfully exploited the security misconfiguration vulnerability."

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>National Security Agency</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; }
            .header { background-color: #003366; color: white; padding: 20px; text-align: center; }
            .nav { overflow: hidden; background-color: #333; }
            .nav a { float: left; display: block; color: #f2f2f2; text-align: center;
                     padding: 14px 16px; text-decoration: none; }
            .nav a:hover { background-color: #ddd; color: black; }
            .content { padding: 20px; }
            .footer { background-color: #003366; color: white; padding: 10px; text-align: center; position: fixed; width: 100%; bottom: 0; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>National Security Agency</h1>
            <p>Securing the Nation through Information Assurance</p>
        </div>
        <div class="nav">
            <a href="/">Home</a>
            <a href="#">About Us</a>
            <a href="#">Services</a>
            <a href="#">Contact</a>
        </div>
        <div class="content">
            <h2>Welcome to the NSA</h2>
            <p>
                The National Security Agency leads the U.S. Government in cryptology 
                that encompasses both Signals Intelligence (SIGINT) and Information Assurance (IA) products and services, 
                and enables Computer Network Operations (CNO) in order to gain a decisive advantage for the nation and our allies.
            </p>
        </div>
        <div class="footer">
            &copy; 2023 National Security Agency
        </div>
    </body>
    </html>
    ''')

@app.route('/error')
def error():
    # Intentional error to trigger the debugger
    return 1 / 0

if __name__ == '__main__':
    app.run(debug=True)