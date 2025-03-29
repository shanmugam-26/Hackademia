from flask import Flask, request, render_template_string

app = Flask(__name__)

product_description = """
<h2>Exclusive Offer: UltraHD Smart TV</h2>
<p>Experience the ultimate viewing experience with our latest UltraHD Smart TV. Limited stock available!</p>
"""

@app.route('/')
def home():
    search_query = request.args.get('search')
    if search_query:
        # Vulnerable to HTML Injection
        content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ShopEasy Online Store</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                <a class="navbar-brand" href="#">ShopEasy</a>
                <div class="collapse navbar-collapse">
                    <ul class="navbar-nav mr-auto">
                        <li class="nav-item active">
                            <a class="nav-link" href="/">Home</a>
                        </li>
                    </ul>
                    <form class="form-inline my-2 my-lg-0" method="get">
                        <input class="form-control mr-sm-2" type="search" name="search" placeholder="Search products" aria-label="Search" value="{search_query}">
                        <button class="btn btn-outline-light my-2 my-sm-0" type="submit">Search</button>
                    </form>
                </div>
            </nav>
            <div class="container mt-5">
                <h1 class="display-4">Welcome to ShopEasy</h1>
                <p class="lead">Your one-stop shop for all your needs.</p>
                <hr class="my-4">
                <p>You searched for: {search_query}</p>
                {product_description}
            </div>
        </body>
        </html>
        """
        return render_template_string(content)
    else:
        content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>ShopEasy Online Store</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
        </head>
        <body>
            <nav class="navbar navbar-expand-lg navbar-dark bg-primary">
                <a class="navbar-brand" href="#">ShopEasy</a>
                <div class="collapse navbar-collapse">
                    <ul class="navbar-nav mr-auto">
                        <li class="nav-item active">
                            <a class="nav-link" href="/">Home</a>
                        </li>
                    </ul>
                    <form class="form-inline my-2 my-lg-0" method="get">
                        <input class="form-control mr-sm-2" type="search" name="search" placeholder="Search products" aria-label="Search">
                        <button class="btn btn-outline-light my-2 my-sm-0" type="submit">Search</button>
                    </form>
                </div>
            </nav>
            <div class="container mt-5">
                <h1 class="display-4">Welcome to ShopEasy</h1>
                <p class="lead">Your one-stop shop for all your needs.</p>
                <hr class="my-4">
                {product_description}
            </div>
        </body>
        </html>
        """
        return render_template_string(content)
if __name__ == '__main__':
        app.run(debug=True)