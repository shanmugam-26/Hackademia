from flask import Flask, render_template_string, request

app = Flask(__name__)

app.config['SECRET_FLAG'] = 'Congratulations! You have found the hidden message.'

home_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Gourmet Palace - Home</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0;}
        header { background-color: #a83232; color: white; padding: 20px; text-align: center;}
        nav a { margin: 10px; color: white; text-decoration: none; }
        section { padding: 20px; }
        footer { background-color: #a83232; color: white; padding: 10px; text-align: center;}
    </style>
</head>
<body>
    <header>
        <h1>Welcome to Gourmet Palace!</h1>
        <nav>
            <a href="/">Home</a>
            <a href="/menu">Menu</a>
            <a href="/about">About Us</a>
            <a href="/reserve">Reservations</a>
        </nav>
    </header>
    <section>
        <h2>Experience the finest dining with us!</h2>
        <p>Indulge in our exquisite cuisines crafted by world-class chefs.</p>
    </section>
    <footer>
        <p>&copy; 2023 Gourmet Palace.</p>
    </footer>
</body>
</html>
'''

menu_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Gourmet Palace - Menu</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0;}
        header { background-color: #a83232; color: white; padding: 20px; text-align: center;}
        nav a { margin: 10px; color: white; text-decoration: none; }
        section { padding: 20px; }
        footer { background-color: #a83232; color: white; padding: 10px; text-align: center;}
        ul { list-style-type: none; padding: 0;}
        li { padding: 5px 0;}
    </style>
</head>
<body>
    <header>
        <h1>Our Menu</h1>
        <nav>
            <a href="/">Home</a>
            <a href="/menu">Menu</a>
            <a href="/about">About Us</a>
            <a href="/reserve">Reservations</a>
        </nav>
    </header>
    <section>
        <h2>Appetizers</h2>
        <ul>
            <li>Bruschetta</li>
            <li>Garlic Bread</li>
            <li>Caprese Salad</li>
        </ul>
        <h2>Main Courses</h2>
        <ul>
            <li>Margherita Pizza</li>
            <li>Spaghetti Carbonara</li>
            <li>Grilled Salmon</li>
        </ul>
        <h2>Desserts</h2>
        <ul>
            <li>Tiramisu</li>
            <li>Panna Cotta</li>
            <li>Gelato</li>
        </ul>
    </section>
    <footer>
        <p>&copy; 2023 Gourmet Palace.</p>
    </footer>
</body>
</html>
'''

about_template = '''
<!DOCTYPE html>
<html>
<head>
    <title>Gourmet Palace - About Us</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0;}
        header { background-color: #a83232; color: white; padding: 20px; text-align: center;}
        nav a { margin: 10px; color: white; text-decoration: none; }
        section { padding: 20px; }
        footer { background-color: #a83232; color: white; padding: 10px; text-align: center;}
    </style>
</head>
<body>
    <header>
        <h1>About Gourmet Palace</h1>
        <nav>
            <a href="/">Home</a>
            <a href="/menu">Menu</a>
            <a href="/about">About Us</a>
            <a href="/reserve">Reservations</a>
        </nav>
    </header>
    <section>
        <p>At Gourmet Palace, we are passionate about delivering an unforgettable dining experience.</p>
        <p>Our mission is to delight your senses with exceptional cuisine and impeccable service.</p>
    </section>
    <footer>
        <p>&copy; 2023 Gourmet Palace.</p>
    </footer>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(home_template)

@app.route('/menu')
def menu():
    return render_template_string(menu_template)

@app.route('/about')
def about():
    return render_template_string(about_template)

@app.route('/reserve', methods=['GET', 'POST'])
def reserve():
    if request.method == 'POST':
        name = request.form.get('name', '')
        date = request.form.get('date', '')
        time_slot = request.form.get('time', '')
        guests = request.form.get('guests', '')
        special_requests = request.form.get('special_requests', '')

        confirmation_template = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Reservation Confirmation</title>
            <style>
            body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0;}
            header { background-color: #a83232; color: white; padding: 20px; text-align: center;}
            nav a { margin: 10px; color: white; text-decoration: none; }
            section { padding: 20px; }
            footer { background-color: #a83232; color: white; padding: 10px; text-align: center;}
            </style>
        </head>
        <body>
            <header>
            <h1>Reservation Confirmation</h1>
            <nav>
                <a href="/">Home</a>
                <a href="/menu">Menu</a>
                <a href="/about">About Us</a>
                <a href="/reserve">Reservations</a>
            </nav>
            </header>
            <section>
            <p>Thank you {{ name|safe }} for your reservation!</p>
            <p>We look forward to serving you on {{ date|safe }} at {{ time_slot|safe }} for {{ guests|safe }} guests.</p>
            <p>Special Requests: {{ special_requests|safe }}</p>
            </section>
            <footer>
            <p>&copy; 2023 Gourmet Palace.</p>
            </footer>
        </body>
        </html>
        '''
        return render_template_string(confirmation_template)
    else:
        reserve_form = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Make a Reservation</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0;}
                header { background-color: #a83232; color: white; padding: 20px; text-align: center;}
                nav a { margin: 10px; color: white; text-decoration: none; }
                section { padding: 20px; }
                footer { background-color: #a83232; color: white; padding: 10px; text-align: center;}
                form { max-width: 400px; margin: auto;}
                input, textarea { width: 100%; margin-bottom: 10px; padding: 8px;}
                input[type="submit"] { background-color: #a83232; color: white; border: none; cursor: pointer;}
            </style>
        </head>
        <body>
            <header>
                <h1>Make a Reservation</h1>
                <nav>
                    <a href="/">Home</a>
                    <a href="/menu">Menu</a>
                    <a href="/about">About Us</a>
                    <a href="/reserve">Reservations</a>
                </nav>
            </header>
            <section>
                <form method="post" action="/reserve">
                    <label>Name:</label>
                    <input type="text" name="name" required><br>
                    <label>Date:</label>
                    <input type="date" name="date" required><br>
                    <label>Time:</label>
                    <input type="time" name="time" required><br>
                    <label>Number of Guests:</label>
                    <input type="number" name="guests" min="1" required><br>
                    <label>Special Requests:</label>
                    <textarea name="special_requests"></textarea><br>
                    <input type="submit" value="Reserve">
                </form>
            </section>
            <footer>
                <p>&copy; 2023 Gourmet Palace.</p>
            </footer>
        </body>
        </html>
        '''
        return render_template_string(reserve_form)

if __name__ == '__main__':
    app.run(debug=True)