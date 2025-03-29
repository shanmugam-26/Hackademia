from flask import Flask, request, render_template_string
import requests

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Fashionista - Redefining Style</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
      <a class="navbar-brand" href="/">Fashionista</a>
      <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav"         aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
    </nav>

    <!-- Main Content -->
    <div class="container mt-5">
        <h1>Welcome to Fashionista</h1>
        <p>Your one-stop destination for the latest trends in fashion.</p>
        <p>Check out our featured products:</p>
        <form action="/product" method="get">
            <div class="form-group">
                <label for="product_url">Enter Product URL:</label>
                <input type="text" class="form-control" id="product_url" name="product_url" placeholder="https://example.com/product">
            </div>
            <button type="submit" class="btn btn-primary">View Product</button>
        </form>
    </div>

    <!-- Footer -->
    <footer class="footer bg-light mt-5 p-3">
        <div class="container">
            <span class="text-muted">© 2023 Fashionista. All rights reserved.</span>
        </div>
    </footer>
</body>
</html>
''')

@app.route('/product')
def product():
    product_url = request.args.get('product_url')
    try:
        response = requests.get(product_url)
        content = response.text

        if 'localhost' in product_url or '127.0.0.1' in product_url:
            return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5 text-center">
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the SSRF vulnerability!</p>
    </div>
</body>
</html>
''')
        else:
            return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Product Details</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <h1>Product Details</h1>
        <div>
            {{ content | safe }}
        </div>
    </div>
</body>
</html>
''', content=content)
    except Exception as e:
        return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Error</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <h1>Error</h1>
        <p>An error occurred: {{ error }}</p>
    </div>
</body>
</html>
''', error=e)
if __name__ == '__main__':
        app.run(debug=True)