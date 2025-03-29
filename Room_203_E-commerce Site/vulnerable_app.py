from flask import Flask, render_template_string

app = Flask(__name__)

bootstrap_cdn = '''
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
'''

home_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>E-commerce Site</title>
    ''' + bootstrap_cdn + '''
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-light bg-light">
  <a class="navbar-brand" href="#">ShopSmart</a>
</nav>
<div class="container mt-4">
  <h1>Welcome to ShopSmart!</h1>
  <p>The best place to buy your favorite gadgets.</p>
  <div class="row">
    <!-- Product 1 -->
    <div class="col-md-4">
      <div class="card">
        <img src="https://via.placeholder.com/300x200" class="card-img-top" alt="Product 1">
        <div class="card-body">
          <h5 class="card-title">Smartphone X</h5>
          <p class="card-text">$999</p>
          <a href="#" class="btn btn-primary">Add to Cart</a>
        </div>
      </div>
    </div>
    <!-- Product 2 -->
    <div class="col-md-4">
      <div class="card">
        <img src="https://via.placeholder.com/300x200" class="card-img-top" alt="Product 2">
        <div class="card-body">
          <h5 class="card-title">Laptop Pro</h5>
          <p class="card-text">$1299</p>
          <a href="#" class="btn btn-primary">Add to Cart</a>
        </div>
      </div>
    </div>
    <!-- Product 3 -->
    <div class="col-md-4">
      <div class="card">
        <img src="https://via.placeholder.com/300x200" class="card-img-top" alt="Product 3">
        <div class="card-body">
          <h5 class="card-title">Wireless Headphones</h5>
          <p class="card-text">$199</p>
          <a href="#" class="btn btn-primary">Add to Cart</a>
        </div>
      </div>
    </div>
  </div>
</div>
</body>
</html>
'''

admin_page = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard</title>
    ''' + bootstrap_cdn + '''
</head>
<body>
<div class="container mt-4">
  <h1>Admin Dashboard</h1>
  <p>Welcome, Admin!</p>
  <p><strong>Congratulations!</strong> You have successfully accessed the admin panel.</p>
</div>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_page)

@app.route('/admin')
def admin():
    # Improper access control: No authentication check
    return render_template_string(admin_page)
if __name__ == '__main__':
      app.run(debug=True)