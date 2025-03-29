from flask import Flask, request, render_template_string
import lxml.etree

app = Flask(__name__)

with open('secret.txt', 'w') as f:
    f.write('Congratulations! You have successfully exploited the XXE vulnerability!')

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Global University - Student Portal</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f0f0f0; color: #333;}
            .container {width: 80%; margin: auto; padding: 20px;}
            header {background-color: #00539C; padding: 10px; color: #fff;}
            nav ul {list-style-type: none; padding: 0;}
            nav li {display: inline; margin-right: 10px;}
            nav a {color: #fff; text-decoration: none;}
            footer {background-color: #00539C; padding: 10px; color: #fff; text-align: center;}
            .content {background-color: #fff; padding: 20px;}
            .form-group {margin-bottom: 15px;}
            label {display: block; margin-bottom: 5px;}
            textarea {width: 100%; padding: 8px; box-sizing: border-box;}
            input[type="submit"] {padding: 10px 20px; background-color: #00539C; color: #fff; border: none; cursor: pointer;}
        </style>
    </head>
    <body>
        <header>
            <h1>Global University - Student Portal</h1>
            <nav>
                <ul>
                    <li><a href="/">Home</a></li>
                    <!-- additional nav items -->
                </ul>
            </nav>
        </header>
        <div class="container">
            <div class="content">
                <h2>Welcome to the Student Portal</h2>
                <p>Please submit your academic records in XML format below:</p>
                <form action="/submit" method="post">
                    <div class="form-group">
                        <label for="xmldata">XML Data:</label>
                        <textarea name="xmldata" id="xmldata" rows="10"></textarea>
                    </div>
                    <input type="submit" value="Submit">
                </form>
            </div>
        </div>
        <footer>
            <p>&copy; 2023 Global University. All rights reserved.</p>
        </footer>
    </body>
    </html>
    ''')

@app.route('/submit', methods=['POST'])
def submit():
    xml_data = request.form['xmldata']
    try:
        parser = lxml.etree.XMLParser(resolve_entities=True)
        tree = lxml.etree.fromstring(xml_data.encode('utf-8'), parser)
        result = lxml.etree.tostring(tree)
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Submission Result</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f0f0f0; color: #333;}
                .container {width: 80%; margin: auto; padding: 20px;}
                .content {background-color: #fff; padding: 20px;}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="content">
                    <h2>Submission Result</h2>
                    <pre>{{ result.decode('utf-8') }}</pre>
                    <a href="/">Go back</a>
                </div>
            </div>
        </body>
        </html>
        ''', result=result)
    except Exception as e:
        return 'An error occurred: ' + str(e)

if __name__ == '__main__':
    app.run(debug=False)