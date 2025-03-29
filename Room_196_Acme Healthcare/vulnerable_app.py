from flask import Flask, render_template_string, send_from_directory, request, abort

app = Flask(__name__)

bootstrap_css = '''
<link
  rel="stylesheet"
  href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"
  integrity="sha384-Vu2Qmgbqlc6uZ9PiF6pf31+pK+0xNo6vUsv/rQNnSaty19WLQuQRlEx9mxRJ8rGL"
  crossorigin="anonymous"
/>
'''

@app.route('/')
def index():
    html_content = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Acme Healthcare</title>
        {bootstrap_css}
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
          <a class="navbar-brand" href="#">Acme Healthcare</a>
          <div class="collapse navbar-collapse">
            <ul class="navbar-nav mr-auto">
              <li class="nav-item active">
                <a class="nav-link" href="/">Home</a>
              </li>
            </ul>
          </div>
        </nav>
        <div class="container">
            <h1 class="mt-5">Welcome to Acme Healthcare</h1>
            <p>Your health is our priority.</p>
            <p>Please <a href="/login">login</a> to access your patient portal.</p>
        </div>
        <!--
        Note: For API access, use your API key in the Authorization header.
        -->
        <script src="/static/js/app.js"></script>
    </body>
    </html>
    '''
    return render_template_string(html_content)

@app.route('/login', methods=['GET', 'POST'])
def login():
    html_content = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Login - Acme Healthcare</title>
        {bootstrap_css}
    </head>
    <body>
        <div class="container">
            <h1 class="mt-5">Patient Portal Login</h1>
            <form method="POST" action="/login">
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    <input 
                        type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="mb-3">
                    <label for="password" 
                    class="form-label">Password</label>
                    <input 
                        type="password" class="form-control" id="password" name="password"
                        required>
                </div>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
            <!-- TODO: Implement login functionality -->
        </div>
    </body>
    </html>
    '''
    if request.method == 'POST':
        # For the purposes of this demo, login always fails
        return render_template_string(html_content + '<div class="alert alert-danger mt-3">Invalid login credentials.</div>')
    return render_template_string(html_content)

@app.route('/static/js/app.js')
def app_js():
    # JavaScript file that contains sensitive data (API key)
    js_content = '''
    // JavaScript code for Acme Healthcare

    // API key for accessing patient data
    const apiKey = 'SECRET_API_KEY_1234567890';

    // Function to get patient data
    async function getPatientData() {
        const response = await fetch('/api/patients', {
            headers: {
                'Authorization': 'Bearer ' + apiKey
            }
        });
        const data = await response.json();
        console.log(data);
    }

    // getPatientData(); // Uncomment to fetch patient data
    '''
    return js_content, 200, {'Content-Type': 'application/javascript'}

@app.route('/api/patients')
def api_patients():
    # Check for Authorization header
    auth_header = request.headers.get('Authorization')
    if auth_header == 'Bearer SECRET_API_KEY_1234567890':
        # Return sensitive patient data
        patient_data = [
            {'name': 'John Doe', 'ssn': '123-45-6789', 'diagnosis': 'Hypertension'},
            {'name': 'Jane Smith', 'ssn': '987-65-4321', 'diagnosis': 'Diabetes'},
            {'name': 'Alice Johnson', 'ssn': '111-22-3333', 'diagnosis': 'Asthma'},
            {'name': 'Bob Brown', 'ssn': '444-55-6666', 'diagnosis': 'Allergies'}
        ]
        # Include a hidden message in the data
        patient_data.append({'message': 'Congratulations! You have found the sensitive data.'})
        return {'patients': patient_data}
    else:
        abort(401)

@app.errorhandler(401)
def unauthorized(e):
    return {'error': 'Unauthorized access'}, 401
if __name__ == '__main__':
        app.run(debug=True)