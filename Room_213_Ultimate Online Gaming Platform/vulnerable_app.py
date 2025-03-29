from flask import Flask, request, render_template_string, redirect, url_for
import requests

app = Flask(__name__)

home_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Ultimate Online Gaming Platform</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
   <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
       <a class="navbar-brand" href="#">Ultimate Gaming</a>
       <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
           <span class="navbar-toggler-icon"></span>
       </button>
       <div class="collapse navbar-collapse" id="navbarNav">
           <ul class="navbar-nav">
               <li class="nav-item active">
                   <a class="nav-link" href="/">Home</a>
               </li>
               <li class="nav-item">
                   <a class="nav-link" href="/news">News</a>
               </li>
           </ul>
       </div>
   </nav>
   <div class="container mt-5">
       <h1>Welcome to the Ultimate Online Gaming Platform!</h1>
       <p>Play the latest games, connect with friends, and explore new worlds.</p>
       <a href="/news" class="btn btn-primary">Latest News</a>
   </div>
</body>
</html>
'''

news_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Game News - Ultimate Gaming</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
   <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
       <a class="navbar-brand" href="#">Ultimate Gaming</a>
       <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
           <span class="navbar-toggler-icon"></span>
       </button>
       <div class="collapse navbar-collapse" id="navbarNav">
           <ul class="navbar-nav">
               <li class="nav-item">
                   <a class="nav-link" href="/">Home</a>
               </li>
               <li class="nav-item active">
                   <a class="nav-link" href="/news">News</a>
               </li>
           </ul>
       </div>
   </nav>
   <div class="container mt-5">
       <h1>Latest Game News</h1>
       <form method="get" action="/news">
           <div class="form-group">
               <label for="url">Enter news source URL:</label>
               <input type="text" class="form-control" id="url" name="url" placeholder="https://example.com/news">
           </div>
           <button type="submit" class="btn btn-primary">Get News</button>
       </form>
       <div class="mt-4">
           {{ content|safe }}
       </div>
   </div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/news', methods=['GET'])
def news():
    url = request.args.get('url')
    if url:
        try:
            response = requests.get(url)
            content = response.text
            # Check for internal URLs to trigger the congratulations message
            if 'localhost' in url or '127.0.0.1' in url:
                content += '<p style="color: green; font-weight: bold;">Congratulations! You have successfully exploited the SSRF vulnerability!</p>'
        except Exception as e:
            content = '<p style="color: red;">Error fetching content: {}</p>'.format(e)
    else:
        content = '<p>Please enter a URL above to fetch news.</p>'
    return render_template_string(news_template, content=content)
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)