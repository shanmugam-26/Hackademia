from flask import Flask, request, render_template_string
import re

app = Flask(__name__)

# Sample data for the fitness center
CLASSES = [
    {'name': 'Yoga for Beginners', 'instructor': 'Alice Smith', 'time': 'Monday 8 AM'},
    {'name': 'Advanced Pilates', 'instructor': 'Bob Johnson', 'time': 'Wednesday 6 PM'},
    {'name': 'Cardio Blast', 'instructor': 'Carol Williams', 'time': 'Friday 7 AM'},
]

# Home page route
@app.route('/', methods=['GET', 'POST'])
def home():
    search_query = ''
    if request.method == 'POST':
        search_query = request.form.get('search', '')
    
    # Vulnerable to HTML Injection
    header_html = f"<h2>Search results for: {search_query}</h2>"
    
    # Filter classes based on search query
    filtered_classes = [cls for cls in CLASSES if search_query.lower() in cls['name'].lower()]
    
    class_list_html = ''
    for cls in filtered_classes:
        class_list_html += f"""
        <div class="class-item">
            <h3>{cls['name']}</h3>
            <p>Instructor: {cls['instructor']}</p>
            <p>Time: {cls['time']}</p>
        </div>
        """
    
    if not filtered_classes and search_query:
        class_list_html = "<p>No classes found matching your search.</p>"
    
    base_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Elite Fitness Center</title>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; }}
            .container {{ width: 80%; margin: auto; overflow: hidden; }}
            #main-header {{ background-color: #35424a; color: #ffffff; padding-top: 30px; text-align: center; }}
            #navbar {{ background-color: #35424a; color: #ffffff; padding: 15px; text-align: center; }}
            #navbar a {{ color: #ffffff; margin: 0 15px; text-decoration: none; }}
            #showcase {{ background-image: url('https://via.placeholder.com/1500x400'); color: #ffffff; height: 400px; text-align: center; }}
            #showcase h1 {{ margin-top: 100px; font-size: 55px; }}
            .search-bar {{ margin: 20px 0; }}
            .class-item {{ background: #ffffff; padding: 20px; margin-bottom: 10px; }}
        </style>
    </head>
    <body>
        <header id="main-header">
            <div class="container">
                <h1>Elite Fitness Center</h1>
            </div>
        </header>
        <nav id="navbar">
            <div class="container">
                <a href="/">Home</a>
                <a href="#">Classes</a>
                <a href="#">Instructors</a>
                <a href="#">Contact</a>
            </div>
        </nav>
        <section id="showcase">
            <div class="container">
                <h1>Reach Your Fitness Goals</h1>
                <p>Join our community and start your journey today!</p>
            </div>
        </section>
        <div class="container">
            <form method="POST" action="/" class="search-bar">
                <input type="text" name="search" placeholder="Search for classes..." value="{search_query}">
                <input type="submit" value="Search">
            </form>
            {{ header_html | safe }}
            {{ class_list_html | safe }}
        </div>
        <footer>
            <div class="container">
                <p>&copy; 2023 Elite Fitness Center</p>
            </div>
        </footer>
    </body>
    </html>
    """
    return render_template_string(base_html)

# Congratulations route
@app.route('/congratulations')
def congratulations():
    return "<h1>Congratulations! You've successfully exploited the vulnerability.</h1>"

if __name__ == '__main__':
    app.run(debug=True)