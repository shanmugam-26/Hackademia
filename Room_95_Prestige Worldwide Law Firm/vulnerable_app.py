from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Prestige Worldwide Law Firm</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
        .header { background-color: #003366; color: #ffffff; padding: 20px; text-align: center; }
        .nav { margin: 0; padding: 0; overflow: hidden; background-color: #333333; }
        .nav li { float: left; list-style-type: none; }
        .nav li a { display: block; color: white; text-align: center; padding: 14px 16px; text-decoration: none; }
        .nav li a:hover { background-color: #111111; }
        .content { padding: 20px; }
    </style>
</head>
<body>

<div class="header">
    <h1>Prestige Worldwide Law Firm</h1>
    <p>Your Trusted Legal Partner</p>
</div>

<ul class="nav">
    <li><a href="/">Home</a></li>
    <li><a href="#">Our Attorneys</a></li>
    <li><a href="#">Practice Areas</a></li>
    <li><a href="#">Contact Us</a></li>
</ul>

<div class="content">
    <h2>Welcome to Prestige Worldwide Law Firm</h2>
    <p>At Prestige Worldwide, we offer top-notch legal services to clients globally.</p>
    <p>Please browse our website to learn more about our services and team.</p>
</div>

<!-- TODO: Remove sensitive data before deployment -->
<!-- API Endpoint: /api/clients -->

</body>
</html>
    ''')

@app.route('/api/clients')
def clients():
    sensitive_data = {
        "message": "Congratulations! You have successfully accessed the confidential client data.",
        "clients": [
            {"name": "John Doe", "ssn": "123-45-6789", "case": "Criminal Defense"},
            {"name": "Jane Smith", "ssn": "987-65-4321", "case": "Corporate Law"},
            {"name": "Robert Johnson", "ssn": "555-55-5555", "case": "Family Law"}
        ]
    }
    return jsonify(sensitive_data)

if __name__ == '__main__':
    app.run(debug=Fals)