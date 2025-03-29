from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Delicious Bites Restaurant</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            .container { width: 80%; margin: auto; background-color: #fff; padding: 20px; }
            h1 { text-align: center; }
            .menu-item { border-bottom: 1px solid #ccc; padding: 10px 0; }
            .order-form { margin-top: 20px; }
            .order-form input[type="text"] { width: 100%; padding: 10px; margin-bottom: 10px; }
            .order-form input[type="submit"] { padding: 10px 20px; background-color: #28a745; color: #fff; border: none; cursor: pointer; }
            .order-form input[type="submit"]:hover { background-color: #218838; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to Delicious Bites</h1>
            <p>Experience the finest dining with our exquisite menu.</p>
            <div class="menu">
                <div class="menu-item">
                    <h3>Grilled Salmon</h3>
                    <p>Freshly caught salmon grilled to perfection.</p>
                    <p><strong>$25</strong></p>
                </div>
                <div class="menu-item">
                    <h3>Steak Diane</h3>
                    <p>Juicy steak with a creamy mushroom sauce.</p>
                    <p><strong>$30</strong></p>
                </div>
                <!-- Add more menu items -->
            </div>

            <div class="order-form">
                <h2>Place Your Order</h2>
                <form method="post">
                    <input type="text" name="credit_card" placeholder="Enter your credit card number" required />
                    <input type="submit" value="Order Now" />
                </form>
            </div>
        </div>
    </body>
    </html>
    '''
    if request.method == 'POST':
        credit_card = request.form.get('credit_card')
        # For demonstration purposes, we simulate insecure communication
        # by including the credit card number in the confirmation page
        print(f"Received credit card number: {credit_card}")
        confirmation_template = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Order Confirmation</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
                .container { width: 80%; margin: auto; background-color: #fff; padding: 20px; text-align: center; }
                h1 { color: green; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Thank you for your order!</h1>
                <p>Your order has been received and is being processed.</p>
                <p>Credit Card Number: ''' + credit_card + '''</p>
                <!-- Hint: check the /congrats endpoint -->
            </div>
        </body>
        </html>
        '''
        return render_template_string(confirmation_template)
    return render_template_string(template)

@app.route('/congrats')
def congrats():
    congrats_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Congratulations</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f2f2f2; }
            .container { width: 80%; margin: auto; background-color: #fff; padding: 20px; text-align: center; }
            h1 { color: blue; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Congratulations!</h1>
            <p>You have successfully exploited the vulnerability.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(congrats_template)

if __name__ == '__main__':
    app.run(debug=True)