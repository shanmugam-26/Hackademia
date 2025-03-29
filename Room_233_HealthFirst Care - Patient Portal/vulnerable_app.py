from flask import Flask, render_template_string, request

app = Flask(__name__)

bootstrap_css = '''
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.1/dist/css/bootstrap.min.css" rel="stylesheet">
'''

index_html = '''
<!doctype html>
<html lang="en">
  <head>
    <title>HealthFirst Care - Patient Portal</title>
    {{ bootstrap_css|safe }}
    <style>
      body {
        background-color: #f8f9fa;
      }
      .navbar {
        background-color: #0062cc;
      }
      .navbar-brand, .nav-link, .footer {
        color: #fff !important;
      }
      .card {
        margin-top: 50px;
      }
      .footer {
        position: fixed;
        bottom: 0;
        width: 100%;
        height: 50px;
        background-color: #0062cc;
        line-height: 50px;
        text-align: center;
      }
    </style>
  </head>
  <body>
    <nav class="navbar navbar-expand-lg">
      <a class="navbar-brand" href="#">HealthFirst Care</a>
    </nav>
    <div class="container">
      <div class="card mx-auto" style="max-width: 500px;">
        <div class="card-body">
          <h5 class="card-title text-center">Patient Portal Login</h5>
          <form method="POST" action="/login">
            <div class="mb-3">
              <label for="patientID" class="form-label">Patient ID</label>
              <input type="text" class="form-control" id="patientID" name="patientID" required>
            </div>
            <div class="mb-3">
              <label for="dob" class="form-label">Date of Birth</label>
              <input type="date" class="form-control" id="dob" name="dob" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Login</button>
          </form>
        </div>
      </div>
    </div>
    <div class="footer">
      &copy; 2023 HealthFirst Care
    </div>
  </body>
</html>
'''

welcome_html = '''
<!doctype html>
<html lang="en">
  <head>
    <title>HealthFirst Care - Welcome</title>
    {{ bootstrap_css|safe }}
  </head>
  <body>
    <div class="container">
      <div class="alert alert-success mt-5" role="alert">
        <h4 class="alert-heading">Welcome back, {{ patient_name }}!</h4>
        <p>Your next appointment is scheduled on {{ next_appointment }}.</p>
      </div>
    </div>
  </body>
</html>
'''

congrats_html = '''
<!doctype html>
<html lang="en">
  <head>
    <title>Congratulations!</title>
    {{ bootstrap_css|safe }}
  </head>
  <body>
    <div class="container">
      <div class="alert alert-info mt-5" role="alert">
        <h4 class="alert-heading">Congratulations!</h4>
        <p>You have successfully exploited the Insecure Communication vulnerability.</p>
      </div>
    </div>
  </body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return render_template_string(index_html, bootstrap_css=bootstrap_css)

@app.route('/login', methods=['POST'])
def login():
    patient_id = request.form.get('patientID')
    dob = request.form.get('dob')
    # Simulated patient data (normally this would be a database lookup)
    patient_data = {
        '123456': {
            'name': 'John Doe',
            'dob': '1985-07-15',
            'next_appointment': '2023-12-01'
        },
        '654321': {
            'name': 'Jane Smith',
            'dob': '1990-03-22',
            'next_appointment': '2023-11-15'
        }
    }
    patient = patient_data.get(patient_id)
    if patient and patient['dob'] == dob:
        resp = render_template_string(welcome_html, bootstrap_css=bootstrap_css,
                                      patient_name=patient['name'],
                                      next_appointment=patient['next_appointment'])
        # Insecure Communication: Setting a cookie with sensitive data without encryption
        resp = app.make_response(resp)
        resp.set_cookie('session', f"patient_id={patient_id}&dob={dob}", httponly=False)
        return resp
    else:
        return render_template_string(index_html, bootstrap_css=bootstrap_css)

@app.route('/debug', methods=['GET'])
def debug():
    # This endpoint is unintentionally exposed and reveals sensitive data
    session_cookie = request.cookies.get('session')
    if session_cookie:
        return render_template_string(congrats_html, bootstrap_css=bootstrap_css)
    else:
        return "Access Denied", 403
if __name__ == '__main__':
        app.run(debug=True)