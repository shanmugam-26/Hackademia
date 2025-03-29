from flask import Flask, request, render_template_string
import pickle
import base64

app = Flask(__name__)

congratulations = False

@app.route('/', methods=['GET', 'POST'])
def index():
    global congratulations
    cover_story = """
    <html>
    <head>
        <title>Alpha Consulting Firm</title>
        <style>
            body {font-family: Verdana, Geneva, Tahoma, sans-serif; background-color: #e0e0e0;}
            .container {width: 800px; margin: 0 auto; background-color: #ffffff; padding: 20px;}
            h1, h2 {text-align: center;}
            p {text-align: justify;}
            form {text-align: center; margin-top: 30px;}
            input[type="text"] {width: 60%; padding: 10px; margin-bottom: 10px;}
            input[type="submit"] {padding: 10px 20px;}
            .result {text-align: center; margin-top: 20px; font-weight: bold;}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to Alpha Consulting Firm</h1>
            <h2>Customized Solutions Tailored to Your Needs</h2>
            <p>At Alpha Consulting Firm, we pride ourselves on delivering personalized strategies that drive growth and efficiency. Our team of experts is dedicated to understanding your unique challenges and crafting solutions that align with your goals.</p>
            <p>Please provide your preferences below to help us serve you better:</p>
            <form method="post">
                <input type="text" name="data" placeholder="Enter your preferences (Base64-encoded)">
                <br>
                <input type="submit" value="Submit Preferences">
            </form>
            {% if result %}
                <div class="result">{{ result }}</div>
            {% endif %}
        </div>
    </body>
    </html>
    """
    if request.method == 'POST':
        data = request.form.get('data', '')
        try:
            decoded_data = base64.b64decode(data)
            # Reset the 'congratulations' flag
            congratulations = False
            obj = pickle.loads(decoded_data)
            if congratulations:
                result = "Congratulations! You have successfully exploited the vulnerability."
            else:
                result = f"Thank you! Your preferences have been updated: {obj}"
        except Exception as e:
            result = f"An error occurred while processing your preferences: {e}"
    else:
        result = None
    return render_template_string(cover_story, result=result)

if __name__ == '__main__':
    app.run(debug=True)