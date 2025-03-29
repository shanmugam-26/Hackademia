from flask import Flask, request, render_template_string

app = Flask(__name__)

secret_flag = "Congratulations! You've found the hidden flag: FLAG-12345"

posts = [
    {'author': 'Alice', 'content': 'Had a great day at the park!'},
    {'author': 'Bob', 'content': 'Loving the new album from my favorite artist.'},
    {'author': 'Charlie', 'content': 'Just finished reading an amazing book!'}
]

@app.route('/')
def home():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
            <head>
                <title>ConnectUs - Home</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
                    .navbar { background-color: #4267B2; padding: 10px; color: white; }
                    .content { width: 50%; margin: auto; }
                    .post { background-color: white; padding: 15px; margin-bottom: 10px; border-radius: 5px; }
                    .search-bar { margin-bottom: 20px; }
                    input[type="text"] { width: 80%; padding: 10px; }
                    input[type="submit"] { padding: 10px; }
                </style>
            </head>
            <body>
                <div class="navbar">
                    <h1>ConnectUs</h1>
                </div>
                <div class="content">
                    <div class="search-bar">
                        <form action="/search" method="post">
                            <input name="query" placeholder="Search ConnectUs..." type="text">
                            <input type="submit" value="Search">
                        </form>
                    </div>
                    <h2>Recent Posts</h2>
                    {% for post in posts %}
                        <div class="post">
                            <strong>{{ post.author }}</strong><br>
                            {{ post.content }}
                        </div>
                    {% endfor %}
                </div>
            </body>
        </html>
    ''', posts=posts)

@app.route('/search', methods=['POST'])
def search():
    query = request.form.get('query', '')

    # Vulnerable code: rendering user input directly
    query_result = render_template_string(query)

    return render_template_string('''
        <!DOCTYPE html>
        <html>
            <head>
                <title>ConnectUs - Search Results</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
                    .navbar { background-color: #4267B2; padding: 10px; color: white; }
                    .content { width: 50%; margin: auto; }
                    .result { background-color: white; padding: 15px; margin-bottom: 10px; border-radius: 5px; }
                    a { text-decoration: none; color: #4267B2; }
                </style>
            </head>
            <body>
                <div class="navbar">
                    <h1>ConnectUs</h1>
                </div>
                <div class="content">
                    <h2>Search Results</h2>
                    <div class="result">
                        {{ query_result }}
                    </div>
                    <p><a href="/">Return to Home</a></p>
                </div>
            </body>
        </html>
    ''')

if __name__ == '__main__':
    app.run(debug=False)