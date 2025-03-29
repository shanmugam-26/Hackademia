from flask import Flask, render_template_string, request, redirect

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Gourmet Garden Restaurant</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fffaf0; color: #333; margin: 0; }
        header { background-color: #556b2f; color: white; padding: 20px; text-align: center; }
        nav a { margin: 0 15px; color: white; text-decoration: none; font-weight: bold; }
        .content { padding: 20px; }
        footer { background-color: #556b2f; color: white; text-align: center; padding: 10px; position: fixed; bottom: 0; width: 100%; }
        .button { background-color: #556b2f; color: white; padding: 10px 20px; text-decoration: none; }
    </style>
</head>
<body>
    <header>
        <h1>Gourmet Garden</h1>
        <nav>
            <a href="/">Home</a>
            <a href="/menu">Menu</a>
            <a href="/reserve">Reservations</a>
            <a href="/contact">Contact Us</a>
        </nav>
    </header>
    <div class="content">
        <h2>Welcome to Gourmet Garden</h2>
        <p>Experience the finest dining amidst a tranquil garden setting. Our menu features seasonal delights crafted from the freshest ingredients.</p>
        <a href="/reserve" class="button">Book a Table</a>
    </div>
    <footer>
        &copy; 2023 Gourmet Garden Restaurant | <a href="/privacy" style="color: white;">Privacy Policy</a>
    </footer>
</body>
</html>''')

@app.route('/reserve')
def reserve():
    return render_template_string('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reserve a Table | Gourmet Garden</title>
    <style>
        /* Similar styling as the home page for consistency */
        body { font-family: Arial, sans-serif; background-color: #fffaf0; color: #333; margin: 0; }
        header { background-color: #556b2f; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; }
        label { display: block; margin-bottom: 5px; }
        input, select { width: 100%; padding: 8px; margin-bottom: 10px; }
        .button { background-color: #556b2f; color: white; padding: 10px 20px; text-decoration: none; }
    </style>
</head>
<body>
    <header>
        <h1>Reserve a Table</h1>
    </header>
    <div class="content">
        <form action="/process_reservation" method="get">
            <label for="date">Date:</label>
            <input type="date" id="date" name="date" required>
            <label for="time">Time:</label>
            <input type="time" id="time" name="time" required>
            <label for="guests">Number of Guests:</label>
            <select id="guests" name="guests">
                {% for i in range(1, 11) %}
                <option value="{{ i }}">{{ i }}</option>
                {% endfor %}
            </select>
            <input type="hidden" name="redirect" value="{{ request.args.get('redirect') }}">
            <button type="submit" class="button">Confirm Reservation</button>
        </form>
    </div>
</body>
</html>''')

@app.route('/process_reservation')
def process_reservation():
    # Process reservation details here (omitted for brevity)
    redirect_url = request.args.get('redirect')
    if redirect_url:
        return redirect(redirect_url)
    else:
        return redirect('/reservation_confirmed')

@app.route('/reservation_confirmed')
def reservation_confirmed():
    return render_template_string('''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reservation Confirmed | Gourmet Garden</title>
    <style>
        /* Styling consistent with other pages */
        body { font-family: Arial, sans-serif; background-color: #fffaf0; color: #333; margin: 0; text-align: center; }
        .content { padding: 50px; }
        .button { background-color: #556b2f; color: white; padding: 10px 20px; text-decoration: none; }
    </style>
</head>
<body>
    <div class="content">
        <h2>Your reservation has been confirmed!</h2>
        <p>We look forward to serving you at Gourmet Garden.</p>
        <a href="/" class="button">Return Home</a>
    </div>
</body>
</html>''')

@app.route('/special_offer')
def special_offer():
    return "Congratulations! You've discovered our hidden special offer!"

if __name__ == '__main__':
    app.run(debug=True)