from flask import Flask, render_template_string, request
import os

app = Flask(__name__)

# Sample data for the social media platform
posts = [
    {'author': 'Alice', 'content': 'Just had a great coffee!'},
    {'author': 'Bob', 'content': 'Enjoying the sunny weather.'},
    {'author': 'Charlie', 'content': 'Check out my new blog post!'}
]

secret = 'Congratulations! You have successfully exploited the SSTI vulnerability.'

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form.get('username', 'Guest')
    else:
        username = 'Guest'

    # SSTI Vulnerability: username is unsanitized in the template
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SocialSphere - Connect with Friends</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        <style>
            /* Add custom styles here */
            body {
                background-color: #f0f2f5;
            }
            .post {
                background-color: white;
                padding: 15px;
                margin-bottom: 15px;
                border-radius: 5px;
            }
            .welcome-message {
                margin-bottom: 30px;
            }
        </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
            <a class="navbar-brand" href="#">SocialSphere</a>
        </nav>
        <div class="container mt-4">
            <div class="welcome-message">
                <h3>Welcome, ''' + username + '''!</h3>
            </div>
            <form method="post" action="/">
                <div class="form-group">
                    <label for="username">Update your status:</label>
                    <input type="text" class="form-control" name="username" id="username" placeholder="What's on your mind?">
                </div>
                <button type="submit" class="btn btn-primary">Post</button>
            </form>
            <hr>
            <h4>Recent Posts</h4>
            {% for post in posts %}
            <div class="post">
                <strong>{{ post.author }}</strong>
                <p>{{ post.content }}</p>
            </div>
            {% endfor %}
        </div>
    </body>
    </html>
    '''

    return render_template_string(template, posts=posts, secret=secret)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)