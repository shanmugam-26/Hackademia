from flask import Flask, render_template, request, redirect, url_for
import os

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <title>TranspoFlex - Your Reliable Transportation Service</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    </head>
    <body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="/">TranspoFlex</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" 
        aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <!-- Navbar content here -->
    </nav>
    <div class="container">
        <h1 class="mt-5">Welcome to TranspoFlex</h1>
        <p>Your one-stop solution for all your transportation needs.</p>
        <p>Experience the best in class services with safety and comfort.</p>
        <!-- More content here -->
    </div>
    </body>
    </html>
    '''

@app.route('/robots.txt')
def robots():
    return '''
    User-agent: *
    Disallow: /admin
    ''', 200, {'Content-Type': 'text/plain'}

@app.route('/admin')
def admin():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <title>Admin Portal - TranspoFlex</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    </head>
    <body>
    <div class="container">
        <h1 class="mt-5">Admin Portal</h1>
        <p>Congratulations! You have found the hidden admin portal.</p>
        <p>Your flag is: FLAG{SecurityMisconfiguration}</p>
    </div>
    </body>
    </html>
    '''
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)