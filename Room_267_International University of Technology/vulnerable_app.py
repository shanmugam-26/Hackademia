from flask import Flask, request, render_template_string, redirect, url_for, make_response, jsonify

app = Flask(__name__)

@app.route('/')
def index():
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>International University of Technology</title>
    <!-- Include modern CSS framework (Bootstrap) -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h1 class="mt-5">Welcome to the International University of Technology</h1>
    <p class="lead">Empowering the next generation of innovators.</p>
    <a href="{{ url_for('login') }}" class="btn btn-primary">Student Portal</a>
</div>
</body>
</html>
""")

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        password = request.form.get('password')
        # Insecure Communication: Credentials are transmitted over HTTP without encryption
        if student_id == 'student123' and password == 'securepassword':
            resp = make_response(redirect(url_for('dashboard')))
            # Insecure Cookie Handling: Session cookie without secure or HttpOnly flags
            resp.set_cookie('session_id', 'abcdef123456')
            return resp
        else:
            error = 'Invalid Student ID or Password. Please try again.'
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Student Login - International University of Technology</title>
    <!-- Include modern CSS framework (Bootstrap) -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Student Login</h2>
    {% if error %}
    <div class="alert alert-danger" role="alert">{{ error }}</div>
    {% endif %}
    <form method="post">
        <div class="form-group">
            <label for="student_id">Student ID</label>
            <input type="text" class="form-control" name="student_id" placeholder="Enter Student ID" required>
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" class="form-control" name="password" placeholder="Enter Password" required>
        </div>
        <button type="submit" class="btn btn-primary">Login</button>
    </form>
</div>
</body>
</html>
""", error=error)

@app.route('/dashboard')
def dashboard():
    session_id = request.cookies.get('session_id')
    if session_id == 'abcdef123456':
        return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - International University of Technology</title>
    <!-- Include modern CSS framework (Bootstrap) -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
<div class="container">
    <h2 class="mt-5">Welcome to your Dashboard</h2>
    <p>Access your courses, grades, and more.</p>
    <a href="{{ url_for('logout') }}" class="btn btn-danger">Logout</a>
</div>
</body>
</html>
""")
    else:
        return redirect(url_for('login'))

@app.route('/api/data')
def api_data():
    # Insecure Communication: Sensitive data exposed over an insecure channel without authentication
    data = {
        'student_id': 'student123',
        'name': 'Alice Smith',
        'courses': ['Computer Science', 'Mathematics', 'Physics'],
        'secret_flag': 'CONGRATULATIONS! You have found the hidden flag.'
    }
    return jsonify(data)

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('session_id', '', expires=0)
    return resp

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)