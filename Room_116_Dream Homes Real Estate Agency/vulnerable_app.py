from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    search = ''
    if request.method == 'POST':
        search = request.form.get('search', '')
    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dream Homes Real Estate Agency</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f2f2f2;
                margin: 0;
                padding: 0;
            }
            .header {
                background-color: #003366;
                color: white;
                padding: 20px;
                text-align: center;
            }
            .content {
                padding: 20px;
            }
            .property {
                background-color: white;
                padding: 10px;
                margin-bottom: 10px;
                border-radius: 5px;
            }
            .property img {
                max-width: 100%;
                border-radius: 5px;
            }
            .search-form {
                margin-bottom: 20px;
            }
        </style>
        <script>
        function congratulations() {
            alert('Congratulations! You have exploited the XSS vulnerability.');
        }
        </script>
    </head>
    <body>
        <div class="header">
            <h1>Dream Homes Real Estate Agency</h1>
        </div>
        <div class="content">
            <form method="post" class="search-form">
                <label for="search">Search for your dream home:</label>
                <input type="text" id="search" name="search">
                <input type="submit" value="Search">
            </form>
            <h2>Results for "{{ search | safe}}":</h2>
            <div class="property">
                <h3>Beautiful Family House</h3>
                <img src="house1.jpg" alt="Family House">
                <p>Located in a peaceful neighborhood, this family house offers comfort and style.</p>
            </div>
            <div class="property">
                <h3>Modern Apartment</h3>
                <img src="apartment.jpg" alt="Modern Apartment">
                <p>A modern apartment in the city center with stunning views.</p>
            </div>
            <div class="property">
                <h3>Cozy Cottage</h3>
                <img src="cottage.jpg" alt="Cozy Cottage">
                <p>A charming cottage in the countryside, perfect for a weekend getaway.</p>
            </div>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html, search=search)

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)