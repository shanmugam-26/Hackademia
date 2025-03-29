from flask import Flask, request, render_template_string, redirect, url_for, make_response
import pickle
import base64

app = Flask(__name__)

products = [
    {'id': 1, 'name': 'Smartphone', 'price': 699},
    {'id': 2, 'name': 'Laptop', 'price': 999},
    {'id': 3, 'name': 'Wireless Headphones', 'price': 199},
    {'id': 4, 'name': 'Smart Watch', 'price': 299},
]

index_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>ShopEasy - Your One-Stop Online Shop</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
        h1 { color: #333; }
        .product { margin-bottom: 20px; }
        .product-name { font-weight: bold; }
        .add-to-cart { background-color: #4CAF50; color: white; padding: 5px 10px; text-decoration: none; }
        .add-to-cart:hover { background-color: #45a049; }
        .cart-link { margin-top: 20px; display: block; }
    </style>
</head>
<body>
    <h1>Welcome to ShopEasy!</h1>
    <h2>Products:</h2>
    <div>
        {% for product in products %}
        <div class="product">
            <span class="product-name">{{ product.name }}</span> - ${{ product.price }}
            <a class="add-to-cart" href="/add_to_cart/{{ product.id }}">Add to Cart</a>
        </div>
        {% endfor %}
    </div>
    <a class="cart-link" href="/cart">View Cart</a>
</body>
</html>
'''

cart_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Your Shopping Cart - ShopEasy</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
        h1 { color: #333; }
        .cart-item { margin-bottom: 10px; }
        .total { font-weight: bold; }
        .back-link { margin-top: 20px; display: block; }
    </style>
</head>
<body>
    <h1>Your Shopping Cart</h1>
    {% if cart %}
    <div>
        {% for item in cart %}
        <div class="cart-item">
            {{ item.name }} - ${{ item.price }}
        </div>
        {% endfor %}
    </div>
    <p class="total">Total: ${{ total }}</p>
    {% else %}
    <p>Your cart is empty.</p>
    {% endif %}
    <a class="back-link" href="/">Continue Shopping</a>
</body>
</html>
'''

congratulations_html = '''
<!DOCTYPE html>
<html>
<head>
    <title>Congratulations!</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #000; color: #0f0; text-align: center; }
        h1 { font-size: 48px; margin-top: 100px; }
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have successfully exploited the vulnerability.</p>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(index_html, products=products)

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    cart = get_cart()
    for product in products:
        if product['id'] == product_id:
            cart.append(product)
            break
    resp = make_response(redirect(url_for('index')))
    set_cart(cart, resp)
    return resp

def get_cart():
    cart_cookie = request.cookies.get('cart')
    if cart_cookie:
        try:
            cart = pickle.loads(base64.b64decode(cart_cookie.encode()))
        except Exception:
            cart = []
    else:
        cart = []
    return cart

def set_cart(cart, resp):
    cart_cookie = base64.b64encode(pickle.dumps(cart)).decode()
    resp.set_cookie('cart', cart_cookie)

@app.route('/cart')
def cart():
    cart = get_cart()
    total = sum(item.get('price', 0) for item in cart)
    # Check for exploitation
    if any(isinstance(item, Surprise) for item in cart):
        return render_template_string(congratulations_html)
    return render_template_string(cart_html, cart=cart, total=total)

# Vulnerable class for exploitation
class Surprise(object):
    def __reduce__(self):
        return (eval, ('__import__("os").system("echo Congratulations! You have exploited the vulnerability.")',))

if __name__ == '__main__':
    app.run(debug=False)