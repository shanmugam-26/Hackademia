from flask import Flask, render_template_string, request, redirect, url_for, abort

app = Flask(__name__)

# Data representing patients. In a real app, this would be in a database.
patients = {
    '1001': {'name': 'John Doe', 'medical_record': 'Allergies: None. Blood Type: A+'},
    '1002': {'name': 'Jane Smith', 'medical_record': 'Allergies: Penicillin. Blood Type: B-'},
    '1003': {'name': 'Alice Johnson', 'medical_record': 'Allergies: Latex. Blood Type: AB+'},
    # ... more patients
    'admin': {'name': 'Admin User', 'medical_record': 'Congratulations! You have found the secret admin record.'}
}

@app.route('/')
def index():
    # Homepage with login form (simulated)
    html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>HealthFirst Provider Portal</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    </head>
    <body>
    <div class="container">
        <h1 class="mt-5">Welcome to HealthFirst Provider Portal</h1>
        <p>Please login to access your medical records.</p>
        <form method="post" action="/login">
            <div class="form-group">
                <label for="patient_id">Patient ID</label>
                <input type="text" class="form-control" id="patient_id" name="patient_id" placeholder="Enter your Patient ID">
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
    </div>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route('/login', methods=['POST'])
def login():
    patient_id = request.form.get('patient_id')
    return redirect(url_for('dashboard', patient_id=patient_id))

@app.route('/patient/<patient_id>')
def dashboard(patient_id):
    patient = patients.get(patient_id)
    if patient:
        if patient_id == 'admin':
            # Display the congratulations prompt
            html = '''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <title>Congratulations!</title>
                <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
            </head>
            <body>
            <div class="container">
                <h1 class="mt-5">Congratulations!</h1>
                <p>You have successfully exploited the IDOR vulnerability. Great job!</p>
            </div>
            </body>
            </html>
            '''
            return render_template_string(html)
        else:
            html = '''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <title>HealthFirst Patient Dashboard</title>
                <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
            </head>
            <body>
            <div class="container">
                <h1 class="mt-5">Patient Dashboard</h1>
                <h3>Hello, {{ patient.name }}</h3>
                <p>Your Medical Record:</p>
                <p>{{ patient.medical_record }}</p>
            </div>
            </body>
            </html>
            '''
            return render_template_string(html, patient=patient)
    else:
        abort(404)
if __name__ == '__main__':
        app.run(debug=True, port=5000)