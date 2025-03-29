from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Create products table
    c.execute('CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT)')
    c.execute('DELETE FROM products')  # Clear existing data
    # Insert some products
    products = [
        ('Acme Software Suite', 'Our flagship software suite for all your needs.'),
        ('Acme CRM', 'Customer Relationship Management software.'),
        ('Acme Project Manager', 'Manage your projects efficiently.'),
        ('Acme Analytics', 'Analytics software for data-driven decisions.'),
    ]
    c.executemany('INSERT INTO products (name, description) VALUES (?, ?)', products)

    # Create a secret table
    c.execute('CREATE TABLE IF NOT EXISTS secret (id INTEGER PRIMARY KEY AUTOINCREMENT, message TEXT)')
    c.execute('DELETE FROM secret')  # Clear existing data
    c.execute('INSERT INTO secret (message) VALUES (?)', ('Congratulations! You have found the secret message.',))
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template_string('''
        <html>
            <head>
                <title>Acme Software Solutions</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f0f0f0; }
                    .header { background-color: #0044cc; color: white; padding: 20px; text-align: center; }
                    .content { margin: 20px; }
                    .search { margin-top: 20px; }
                    .footer { background-color: #0044cc; color: white; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
                    input[type="text"] { padding: 5px; width: 300px; }
                    input[type="submit"] { padding: 5px 10px; }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Acme Software Solutions</h1>
                </div>
                <div class="content">
                    <h2>Welcome to Acme Software Solutions</h2>
                    <p>Your partner in innovative software solutions.</p>
                    <div class="search">
                        <form action="/search" method="GET">
                            <input type="text" name="query" placeholder="Search our products">
                            <input type="submit" value="Search">
                        </form>
                    </div>
                </div>
                <div class="footer">
                    &copy; 2023 Acme Software Solutions
                </div>
            </body>
        </html>
    ''')

@app.route('/search')
def search():
    query = request.args.get('query', '')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    sql_query = "SELECT * FROM products WHERE name LIKE '%{}%'".format(query)
    c.execute(sql_query)
    results = c.fetchall()

    # Check if the secret message has been retrieved
    secret_message = ''
    for row in results:
        if 'Congratulations!' in row[1] or 'Congratulations!' in row[2]:
            secret_message = row[1] if 'Congratulations!' in row[1] else row[2]

    conn.close()
    if secret_message:
        return render_template_string('''
            <html>
                <head>
                    <title>Congratulations!</title>
                    <style>
                        body { font-family: Arial, sans-serif; background-color: #f0f0f0; text-align: center; padding-top: 50px; }
                        h1 { color: green; }
                    </style>
                </head>
                <body>
                    <h1>{{ secret_message }}</h1>
                </body>
            </html>
        ''', secret_message=secret_message)
    elif len(results) == 0:
        return render_template_string('''
            <html>
                <head>
                    <title>Search Results</title>
                    <style>
                        body { font-family: Arial, sans-serif; background-color: #f0f0f0; }
                        .content { margin: 20px; text-align: center; }
                        a { text-decoration: none; color: #0044cc; }
                    </style>
                </head>
                <body>
                    <div class="content">
                        <h2>No results found for "{{ query }}".</h2>
                        <a href="/">Back to home</a>
                    </div>
                </body>
            </html>
        ''', query=query)
    else:
        products_html = ''
        for product in results:
            products_html += '<h3>{}</h3><p>{}</p>'.format(product[1], product[2])

        return render_template_string('''
            <html>
                <head>
                    <title>Search Results</title>
                    <style>
                        body { font-family: Arial, sans-serif; background-color: #f0f0f0; }
                        .content { margin: 20px; }
                        h3 { color: #0044cc; }
                    </style>
                </head>
                <body>
                    <div class="content">
                        <h2>Search Results for "{{ query }}":</h2>
                        <div>
                            {{ products_html|safe }}
                        </div>
                        <a href="/">Back to home</a>
                    </div>
                </body>
            </html>
        ''', query=query, products_html=products_html)

if __name__ == '__main__':
    init_db()
    app.run()