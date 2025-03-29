from flask import Flask, request, render_template_string
import lxml.etree

# Create the secret file
with open('secret.txt', 'w') as f:
    f.write('Congratulations! You have found the secret!')

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        xml_data = request.form.get('xml_data')
        try:
            parser = lxml.etree.XMLParser(resolve_entities=True)
            root = lxml.etree.fromstring(xml_data, parser)
            route = root.find('Route').text
            if 'Congratulations! You have found the secret!' in route:
                return render_template_string('<h1>Congratulations! You have exploited the XXE vulnerability!</h1>')
            else:
                return render_template_string('<h1>Processing Route: {{route}}</h1>', route=route)
        except Exception as e:
            return render_template_string('<h1>Error processing XML data</h1><p>{{error}}</p>', error=str(e))
    else:
        return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <title>QuickTrans Transportation Service</title>
    <style>
    /* Basic styles for the page */
    body { font-family: Arial, sans-serif; background-color: #f0f0f0; margin: 0; }
    header { background-color: #283593; color: #fff; padding: 20px; text-align: center; }
    h1 { margin: 0; }
    form { background-color: #fff; padding: 20px; max-width: 600px; margin: 40px auto; border-radius: 8px; }
    textarea { width: 100%; padding: 10px; border-radius: 4px; border: 1px solid #ccc; }
    input[type="submit"] { background-color: #283593; color: #fff; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
    </style>
</head>
<body>
    <header>
        <h1>Welcome to QuickTrans Transportation Service</h1>
    </header>
    <form method="POST">
        <h2>Get Your Personalized Route Plan</h2>
        <p>Please enter your route request in XML format:</p>
        <textarea name="xml_data" rows="10" placeholder="&lt;Request&gt;&#10;    &lt;Route&gt;Your destination&lt;/Route&gt;&#10;&lt;/Request&gt;"></textarea>
        <br><br>
        <input type="submit" value="Submit Request">
    </form>
</body>
</html>''')

if __name__ == '__main__':
    app.run(debug=True)