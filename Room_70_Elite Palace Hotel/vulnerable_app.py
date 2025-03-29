from flask import Flask, render_template_string, request

app = Flask(__name__)

hotel_data = {
    'name': 'Elite Palace Hotel',
    'description': 'An oasis of luxury and comfort in the bustling city center.',
    'rooms': [
        {'type': 'Executive Suite', 'price': '$500/night'},
        {'type': 'Presidential Suite', 'price': '$800/night'},
        {'type': 'Royal Suite', 'price': '$1200/night'},
    ],
    'amenities': ['High-Speed Wi-Fi', 'Infinity Pool', 'Wellness Spa', 'State-of-the-art Gym', 'Gourmet Dining', 'Sky Lounge']
}

@app.route('/')
def index():
    template = '''
    <!doctype html>
    <html lang="en">
    <head>
        <title>{{ hotel.name }}</title>
        <style>
            body {font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; margin:0; padding:0; color:#1a1a1a; background-color:#f4f4f4;}
            .header {background-color:#2c3e50; color:#ecf0f1; padding:40px; text-align:center;}
            .content {padding:40px;}
            .room {background-color:#ecf0f1; padding:20px; margin-bottom:20px; border-radius:5px;}
            .amenities {list-style:none; padding:0;}
            .amenities li {display:inline-block; background-color:#3498db; color:#fff; padding:10px 15px; margin:5px; border-radius:3px;}
            .footer {background-color:#2c3e50; color:#ecf0f1; padding:20px; text-align:center;}
            .search-box {margin-top:30px;}
            .search-box input[type="text"] {padding:10px; width:300px; border:1px solid #ccc; border-radius:3px;}
            .search-box input[type="submit"] {padding:10px 20px; background-color:#3498db; color:#fff; border:none; border-radius:3px; cursor:pointer;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>{{ hotel.name }}</h1>
            <p>{{ hotel.description }}</p>
        </div>
        <div class="content">
            <h2>Our Exclusive Rooms</h2>
            {% for room in hotel.rooms %}
            <div class="room">
                <h3>{{ room.type }}</h3>
                <p>Price: {{ room.price }}</p>
            </div>
            {% endfor %}
            <h2>World-Class Amenities</h2>
            <ul class="amenities">
                {% for amenity in hotel.amenities %}
                <li>{{ amenity }}</li>
                {% endfor %}
            </ul>
            <div class="search-box">
                <h2>Explore More</h2>
                <form method="GET" action="/search">
                    <input type="text" name="q" placeholder="Search our services" required />
                    <input type="submit" value="Search" />
                </form>
            </div>
        </div>
        <div class="footer">
            <p>&copy; 2023 Elite Palace Hotel. All rights reserved.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, hotel=hotel_data)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Intentional SSTI vulnerability
    template = '''
    {% set secret = "Congratulations! You have successfully exploited the SSTI vulnerability!" %}
    <!doctype html>
    <html lang="en">
    <head>
        <title>Search Results for ''' + query + '''</title>
    </head>
    <body>
        <div class="header">
            <h1>Search Results</h1>
        </div>
        <div class="content">
            <p>Your search for "<strong>''' + query + '''</strong>" did not match any of our services.</p>
            <p>Please try again with different keywords.</p>
        </div>
        <div class="footer">
            <p>&copy; 2023 Elite Palace Hotel. All rights reserved.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)