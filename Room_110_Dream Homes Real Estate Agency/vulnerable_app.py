from flask import Flask, request, render_template_string, make_response
import pickle
import base64

app = Flask(__name__)

@app.route('/')
def index():
    # Retrieve user preferences if they exist
    user_prefs = request.cookies.get('prefs')
    if user_prefs:
        try:
            # Insecure deserialization vulnerability
            prefs = pickle.loads(base64.b64decode(user_prefs))
        except:
            prefs = {}
    else:
        prefs = {}

    # Check if user has exploited the vulnerability
    admin_message = ''
    if prefs.get('is_admin'):
        admin_message = '''
        <div style="background-color: #d4edda; padding: 20px; margin: 20px 0; border-radius: 5px;">
            <h2 style="color: #155724;">Congratulations!</h2>
            <p>You have successfully exploited the vulnerability.</p>
        </div>
        '''

    # Generate personalized content based on preferences
    personalized_message = ''
    if prefs.get('location') or prefs.get('price_range'):
        personalized_message = '''
        <div style="background-color: #cce5ff; padding: 20px; margin: 20px 0; border-radius: 5px;">
            <h2 style="color: #004085;">Personalized Recommendations</h2>
            <p>Showing properties in <strong>{location}</strong> within <strong>{price_range}</strong> price range.</p>
        </div>
        '''.format(
            location=prefs.get('location', 'any location'),
            price_range=prefs.get('price_range', 'any')
        )

    # Render the page with properties and personalization
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dream Homes Real Estate Agency</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f8f9fa; margin: 0; }}
            .header {{ background-color: #343a40; padding: 20px; text-align: center; color: #ffffff; }}
            .navigation {{ overflow: hidden; background-color: #333; }}
            .navigation a {{ float: left; display: block; color: #f2f2f2; text-align: center;
                             padding: 14px 16px; text-decoration: none; }}
            .navigation a:hover {{ background-color: #ddd; color: black; }}
            .content {{ padding: 20px; }}
            .property {{ background-color: #ffffff; padding: 20px; margin: 20px 0; border-radius: 5px;
                         box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2); }}
            .property h3 {{ margin-top: 0; }}
            .footer {{ background-color: #343a40; padding: 10px; text-align: center; color: #ffffff; }}
            .button {{
                background-color: #28a745; border: none; color: white; padding: 10px 24px;
                text-align: center; text-decoration: none; display: inline-block; font-size: 16px;
                margin: 4px 2px; cursor: pointer; border-radius: 4px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Dream Homes Real Estate Agency</h1>
            <p>Your dream home awaits.</p>
        </div>
        <div class="navigation">
            <a href="/">Home</a>
            <a href="#properties">Properties</a>
            <a href="#contact">Contact Us</a>
        </div>
        <div class="content">
            {admin_message}
            {personalized_message}
            <h2 id="properties">Featured Properties</h2>
            <div class="property">
                <h3>Luxury Villa in Beverly Hills</h3>
                <p>Experience the epitome of luxury in this stunning villa located in the heart of Beverly Hills.</p>
                <button class="button">View Details</button>
            </div>
            <div class="property">
                <h3>Modern Apartment in New York City</h3>
                <p>A sleek and modern apartment with breathtaking views of the city skyline.</p>
                <button class="button">View Details</button>
            </div>
            <div class="property">
                <h3>Cozy Cottage in the Countryside</h3>
                <p>Escape to the tranquility of this charming cottage surrounded by nature.</p>
                <button class="button">View Details</button>
            </div>
            <h2>Set Your Preferences</h2>
            <form action="/set_prefs" method="post">
                <label for="location">Preferred Location:</label><br>
                <input type="text" id="location" name="location" placeholder="e.g., New York"><br><br>
                <label for="price_range">Price Range:</label><br>
                <input type="text" id="price_range" name="price_range" placeholder="e.g., $500,000 - $1,000,000"><br><br>
                <input type="submit" value="Save Preferences" class="button">
            </form>
        </div>
        <div class="footer">
            <p>&copy; 2023 Dream Homes Real Estate Agency</p>
        </div>
    </body>
    </html>
    '''.format(admin_message=admin_message, personalized_message=personalized_message)

    response = make_response(render_template_string(html))
    return response

@app.route('/set_prefs', methods=['POST'])
def set_prefs():
    # Get preferences from user input
    prefs = {
        'location': request.form.get('location', ''),
        'price_range': request.form.get('price_range', '')
    }
    # Serialize the preferences
    serialized_prefs = base64.b64encode(pickle.dumps(prefs)).decode('utf-8')
    response = make_response('''
        <h2>Preferences Saved!</h2>
        <p>Your preferences have been saved successfully.</p>
        <a href="/" class="button">Return to Home Page</a>
    ''')
    # Set the preferences in a cookie
    response.set_cookie('prefs', serialized_prefs)
    return response

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)