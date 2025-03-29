from flask import Flask, request, render_template_string

app = Flask(__name__)

# Simulating a news article with comments section
news_article = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Daily News</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 50px; background-color: #f4f4f4; }
        .container { background-color: #fff; padding: 20px; border-radius: 5px; }
        h1 { color: #333; }
        .comment-section { margin-top: 40px; }
        .comment { border-bottom: 1px solid #ddd; padding: 10px 0; }
        .comment:last-child { border-bottom: none; }
        .comment h4 { margin: 0; }
        .comment p { margin: 5px 0 0 0; }
        form { margin-top: 20px; }
        input[type="text"] { width: 80%; padding: 10px; }
        input[type="submit"] { padding: 10px 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Breakthrough in Renewable Energy Announced</h1>
        <p>Scientists have made a significant breakthrough in renewable energy technology that could lead to more efficient solar panels and longer-lasting batteries...</p>
        
        <div class="comment-section">
            <h2>Comments:</h2>
            {% if comments %}
                {% for comment in comments %}
                    <div class="comment">
                        <h4>User {{ loop.index }}:</h4>
                        <p>{{ comment|safe }}</p>
                    </div>
                {% endfor %}
            {% else %}
                <p>No comments yet. Be the first to comment!</p>
            {% endif %}
            <form method="post">
                <input type="text" name="comment" placeholder="Enter your comment here" required>
                <input type="submit" value="Post Comment">
            </form>
        </div>
    </div>
</body>
</html>
"""

# Vulnerable route
@app.route('/', methods=['GET', 'POST'])
def index():
    comments = []
    if request.method == 'POST':
        new_comment = request.form.get('comment')
        comments.append(new_comment)
        # Intentional vulnerability: rendering user input without sanitization
        return render_template_string(news_article, comments=comments)
    return render_template_string(news_article, comments=comments)

# Congratulatory message for exploiting the vulnerability
@app.route('/congratulations')
def congratulations():
    return "<h1>Congratulations! You've successfully exploited the HTML Injection vulnerability.</h1>"

if __name__ == '__main__':
    app.jinja_env.autoescape = False
    app.run(debug=True)