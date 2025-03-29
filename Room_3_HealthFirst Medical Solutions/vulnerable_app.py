from flask import Flask, request, render_template_string, redirect, url_for, session
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Sample user data and patient records
users = {
    'johndoe': {'password': 'password123', 'patient_id': '1'},
    'janesmith': {'password': 'securepass', 'patient_id': '2'},
}

patients = {
    '1': {
        'name': 'John Doe',
        'dob': '1985-06-15',
        'records': [
            {'date': '2023-01-10', 'diagnosis': 'Common Cold', 'treatment': 'Rest and hydration'},
            {'date': '2023-08-21', 'diagnosis': 'Sprained Ankle', 'treatment': 'Physical therapy'}
        ]
    },
    '2': {
        'name': 'Jane Smith',
        'dob': '1990-09-22',
        'records': [
            {'date': '2023-02-14', 'diagnosis': 'Allergies', 'treatment': 'Antihistamines'},
            {'date': '2023-07-30', 'diagnosis': 'Flu', 'treatment': 'Antiviral medication'}
        ]
    },
    # Other patient records...
}

# Key patient record for the challenge
patients['99'] = {
    'name': 'Congratulations!',
    'dob': '',
    'records': [
        {'date': '', 'diagnosis': 'You have successfully exploited the IDOR vulnerability!', 'treatment': ''}
    ]
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    home_page = '''
    <!doctype html>
    <html>
    <head>
        <title>HealthFirst Medical Solutions</title>
        <style>
            body {font-family: Arial, sans-serif; background-color: #f0f8ff; margin: 0; padding: 0;}
            .header {background-color: #003366; color: #ffffff; padding: 20px; text-align: center;}
            .content {padding: 20px;}
            .footer {background-color: #003366; color: #ffffff; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}
            .button {background-color: #0073e6; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; border-radius: 5px;}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Welcome to HealthFirst Medical Solutions</h1>
        </div>
        <div class="content">
            <h2>Your health is our priority</h2>
            <p>At HealthFirst, we provide top-notch healthcare services to ensure you and your family stay healthy.</p>
            <p>Access your medical records online anytime, anywhere.</p>
            <a href="/login" class="button">Login to Your Account</a>
        </div>
        <div class="footer">
            &copy; 2023 HealthFirst Medical Solutions
        </div>
    </body>
    </html>
    '''
    return home_page

@app.route('/login', methods=['GET', 'POST'])
def login():
    login_page = '''
    <!doctype html>
    <html>
    <head>
        <title>HealthFirst Medical Solutions - Login</title>
        <style>
            body {{font-family: Arial, sans-serif; background-color: #f0f8ff; margin: 0; padding: 0;}}
            .header {{background-color: #003366; color: #ffffff; padding: 20px; text-align: center;}}
            .content {{padding: 20px;}}
            .footer {{background-color: #003366; color: #ffffff; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}}
            .button {{background-color: #0073e6; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; border-radius: 5px;}}
            .login-form {{max-width: 300px; margin: auto;}}
            input[type=text], input[type=password] {{
                width: 100%;
                padding: 12px 20px;
                margin: 8px 0;
                display: inline-block;
                border: 1px solid #ccc;
                box-sizing: border-box;
            }}
            button {{
                background-color: #0073e6;
                color: white;
                padding: 14px 20px;
                margin: 8px 0;
                border: none;
                cursor: pointer;
                width: 100%;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Login to Your Account</h1>
        </div>
        <div class="content">
            <div class="login-form">
                <form method="post">
                    <label for="username">Username:</label><br>
                    <input type="text" id="username" name="username" required><br>
                    <label for="password">Password:</label><br>
                    <input type="password" id="password" name="password" required><br><br>
                    <button type="submit">Login</button>
                </form>
            </div>
        </div>
        <div class="footer">
            &copy; 2023 HealthFirst Medical Solutions
        </div>
    </body>
    </html>
    '''

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and users[username]['password'] == password:
            session['username'] = username
            # Redirect to records page
            return redirect(url_for('records'))
        else:
            # Invalid credentials
            return render_template_string(login_page + '<p style="color:red; text-align:center;">Invalid username or password</p>')
    else:
        return login_page

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/records')
@login_required
def records():
    # Get the patient_id from the request arguments
    patient_id = request.args.get('patient_id')

    # Insecure Direct Object Reference vulnerability:
    # The application fails to verify that the requested patient_id belongs to the logged-in user.
    # It directly uses the provided patient_id to fetch records.

    if not patient_id:
        # If no patient_id is provided, default to the patient's own ID
        username = session['username']
        patient_id = users[username]['patient_id']

        # Redirect to URL with patient_id parameter (this behavior helps expose the vulnerability)
        return redirect(url_for('records', patient_id=patient_id))

    if patient_id in patients:
        patient = patients[patient_id]
        records_html = ''
        for record in patient['records']:
            records_html += f'''
            <tr>
                <td>{record['date']}</td>
                <td>{record['diagnosis']}</td>
                <td>{record['treatment']}</td>
            </tr>
            '''
        records_page = f'''
        <!doctype html>
        <html>
        <head>
            <title>HealthFirst Medical Solutions - Patient Records</title>
            <style>
                body {{font-family: Arial, sans-serif; background-color: #f0f8ff; margin: 0; padding: 0;}}
                .header {{background-color: #003366; color: #ffffff; padding: 20px; text-align: center;}}
                .content {{padding: 20px;}}
                .footer {{background-color: #003366; color: #ffffff; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}}
                table {{width: 100%; border-collapse: collapse;}}
                th, td {{border: 1px solid #ddd; padding: 8px;}}
                th {{background-color: #f2f2f2;}}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Patient Medical Records</h1>
            </div>
            <div class="content">
                <h2>Patient Name: {patient['name']}</h2>
                <p>Date of Birth: {patient['dob']}</p>
                <table>
                    <tr>
                        <th>Date</th>
                        <th>Diagnosis</th>
                        <th>Treatment</th>
                    </tr>
                    {records_html}
                </table>
            </div>
            <div class="footer">
                &copy; 2023 HealthFirst Medical Solutions
            </div>
        </body>
        </html>
        '''
    else:
        records_page = '''
        <!doctype html>
        <html>
        <head>
            <title>HealthFirst Medical Solutions - Error</title>
            <style>
                body {font-family: Arial, sans-serif; background-color: #f0f8ff; margin: 0; padding: 0;}
                .header {background-color: #003366; color: #ffffff; padding: 20px; text-align: center;}
                .content {padding: 20px;}
                .footer {background-color: #003366; color: #ffffff; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%;}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Error</h1>
            </div>
            <div class="content">
                <p>Invalid patient ID.</p>
            </div>
            <div class="footer">
                &copy; 2023 HealthFirst Medical Solutions
            </div>
        </body>
        </html>
        '''
    return records_page

if __name__ == '__main__':
    app.run(debug=True)