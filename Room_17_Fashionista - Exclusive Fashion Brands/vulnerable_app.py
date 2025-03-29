from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Fashionista - Exclusive Fashion Brands</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f0f0f0; margin: 0; }}
        .header {{ background-color: #333; color: #fff; padding: 20px; text-align: center; }}
        .container {{ padding: 20px; }}
        .search-box {{ margin-bottom: 20px; }}
        .search-box input[type="text"] {{
            width: 80%%;
            padding: 10px;
            font-size: 16px;
        }}
        .search-box input[type="submit"] {{
            padding: 10px 20px;
            font-size: 16px;
            background-color: #333;
            color: #fff;
            border: none;
        }}
        .product {{
            background-color: #fff;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
        }}
        .product h2 {{ margin: 0; }}
        .product p {{ margin: 5px 0 0 0; }}
        .congrats {{ background-color: #dff0d8; color: #3c763d; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Fashionista</h1>
        <p>Your ultimate destination for luxury fashion brands.</p>
    </div>
    <div class="container">
        <div class="search-box">
            <form method="GET" action="/">
                <input type="text" name="product" placeholder="Search for products..." />
                <input type="submit" value="Search" />
            </form>
        </div>
        {% if flag %}
        <div class="congrats">
            <h2>{{ flag }}</h2>
        </div>
        {% endif %}
        {% for product in products %}
        <div class="product">
            <h2>{{ product[1] }}</h2>
            <p>Price: ${{ product[2] }}</p>
        </div>
        {% endfor %}
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def home():
    product_name = request.args.get('product', '')
    conn = sqlite3.connect('fashion.db')
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE name LIKE '%%{}%%'".format(product_name)
    try:
        cursor.execute(query)
        products = cursor.fetchall()
    except Exception as e:
        products = []
    flag = None
    if 'admin' in product_name.lower():
        try:
            cursor.execute("SELECT flag FROM secret")
            flag = cursor.fetchone()[0]
        except:
            pass
    conn.close()
    return render_template_string(HTML_TEMPLATE, products=products, flag=flag)

def init_db():
    conn = sqlite3.connect('fashion.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS secret (
            flag TEXT NOT NULL
        )
    ''')
    cursor.execute("DELETE FROM products")
    cursor.execute("DELETE FROM secret")
    cursor.execute("INSERT INTO products (name, price) VALUES ('Elegant Evening Gown', 299.99)")
    cursor.execute("INSERT INTO products (name, price) VALUES ('Stylish Leather Jacket', 199.99)")
    cursor.execute("INSERT INTO products (name, price) VALUES ('Classic White Shirt', 49.99)")
    cursor.execute("INSERT INTO products (name, price) VALUES ('Designer Handbag', 499.99)")
    cursor.execute("INSERT INTO secret (flag) VALUES ('Congratulations! You have successfully exploited the SQL Injection vulnerability.')")
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)