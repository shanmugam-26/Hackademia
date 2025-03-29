from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global News Network - Breaking News, Latest Headlines</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .navbar { margin-bottom: 20px; }
        .headline { font-size: 2.5rem; font-weight: bold; }
        .lead-article { margin-bottom: 40px; }
        .article { margin-bottom: 20px; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="/">Global News Network</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"         aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
             <ul class="navbar-nav mr-auto">
                 <li class="nav-item active">
                     <a class="nav-link" href="/">Home <span class="sr-only">(current)</span></a>
                 </li>
                 <li class="nav-item">
                     <a class="nav-link" href="#">World</a>
                 </li>
                 <li class="nav-item">
                     <a class="nav-link" href="#">Politics</a>
                 </li>
                 <li class="nav-item">
                     <a class="nav-link" href="#">Business</a>
                 </li>
                 <li class="nav-item">
                     <a class="nav-link" href="#">Technology</a>
                 </li>
                 <li class="nav-item">
                     <a class="nav-link" href="#">Entertainment</a>
                 </li>
             </ul>
             <form class="form-inline my-2 my-lg-0" action="/search">
                 <input class="form-control mr-sm-2" type="search" placeholder="Search" aria-label="Search" name="q">
                 <button class="btn btn-outline-success my-2 my-sm-0" type="submit">Search</button>
             </form>
         </div>
     </nav>
     <div class="container">
         <div class="lead-article">
             <h1 class="headline">Breaking: Major Event Unfolds</h1>
             <p class="text-muted">By Jane Doe | October 15, 2023</p>
             <p>In a surprising turn of events, something significant has happened. Stay tuned for more details as the story develops.</p>
         </div>
         <div class="row">
             <div class="col-md-4 article">
                 <h2>World News</h2>
                 <p>Latest updates from around the globe.</p>
             </div>
             <div class="col-md-4 article">
                 <h2>Politics</h2>
                 <p>Insights into political movements and decisions.</p>
             </div>
             <div class="col-md-4 article">
                 <h2>Technology</h2>
                 <p>Advancements and innovations in tech.</p>
             </div>
         </div>
     </div>
     <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
     <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/js/bootstrap.bundle.min.js"></script>
 </body>
 </html>'''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    from markupsafe import escape
    query = escape(query)
    template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Search Results - Global News Network</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
        .navbar {{ margin-bottom: 20px; }}
        .search-results {{ margin-top: 20px; }}
        .alert-congrats {{ margin-top: 20px; }}
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <a class="navbar-brand" href="/">Global News Network</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"         aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
             <ul class="navbar-nav mr-auto">
                 <li class="nav-item">
                     <a class="nav-link" href="/">Home</a>
                 </li>
                 <li class="nav-item">
                     <a class="nav-link" href="#">World</a>
                 </li>
                 <li class="nav-item">
                     <a class="nav-link" href="#">Politics</a>
                 </li>
                 <li class="nav-item">
                     <a class="nav-link" href="#">Business</a>
                 </li>
                 <li class="nav-item">
                     <a class="nav-link" href="#">Technology</a>
                 </li>
                 <li class="nav-item">
                     <a class="nav-link" href="#">Entertainment</a>
                 </li>
             </ul>
             <form class="form-inline my-2 my-lg-0" action="/search">
                 <input class="form-control mr-sm-2" type="search" placeholder="Search" aria-label="Search" name="q" value="{{ query }}">
                 <button class="btn btn-outline-success my-2 my-sm-0" type="submit">Search</button>
             </form>
         </div>
     </nav>
     <div class="container">
         <div class="search-results">
             <h2>Search Results for '{{ query }}'</h2>
             <p>No articles found matching your search terms.</p>
         </div>
     </div>
     {{ congrats }}
     <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
     <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/js/bootstrap.bundle.min.js"></script>
 </body>
 </html>'''
    return render_template_string(template, query=query, congrats='')
    return render_template_string(template)
if __name__ == '__main__':
        app.jinja_env.autoescape = False
        app.run(debug=True)