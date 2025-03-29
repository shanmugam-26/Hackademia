from flask import Flask, request, render_template_string

app = Flask(__name__)

# Simulated database of student grades
students = {
    '1001': {'name': 'Alice Smith', 'grades': {'Mathematics': 'A', 'Science': 'B+'}},
    '1002': {'name': 'Bob Johnson', 'grades': {'Mathematics': 'B', 'Science': 'A-'}},
    '1003': {'name': 'Charlie Lee', 'grades': {'Mathematics': 'A-', 'Science': 'A'}},
    # Secret student for the challenge
    '9999': {'name': 'Congratulations!', 'grades': {'Secret Message': 'You have found the hidden content!'}},
}

# HTML template with modern CSS (Bootstrap)
template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Global Academy Student Portal</title>
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
  <div class="container-fluid">
    <a class="navbar-brand" href="#">Global Academy</a>
  </div>
</nav>
<div class="container py-5">
    <h1 class="text-center mb-4">Welcome, {{ student.name }}</h1>
    <div class="card">
        <div class="card-header">
            <h3>Your Grades</h3>
        </div>
        <ul class="list-group list-group-flush">
            {% for subject, grade in student.grades.items() %}
            <li class="list-group-item d-flex justify-content-between align-items-center">
                {{ subject }}
                <span class="badge bg-primary rounded-pill">{{ grade }}</span>
            </li>
            {% endfor %}
        </ul>
    </div>
    {% if student_id == '9999' %}
    <div class="alert alert-success mt-4" role="alert">
        Congratulations! You've successfully exploited the IDOR vulnerability.
    </div>
    {% endif %}
</div>
<!-- Bootstrap JS and dependencies -->
<script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

@app.route('/')
def index():
    # Insecure Direct Object Reference vulnerability: 'student_id' parameter is not properly secured
    student_id = request.args.get('student_id', '1001')
    student = students.get(student_id)
    if student:
        return render_template_string(template, student=student, student_id=student_id)
    else:
        return render_template_string('''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Global Academy Student Portal</title>
                <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
                <!-- Bootstrap CSS -->
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
            </head>
            <body class="bg-light">
            <div class="container py-5">
                <div class="alert alert-danger" role="alert">
                    Student not found.
                </div>
            </div>
            </body>
            </html>
        '''), 404
if __name__ == '__main__':
        app.run(debug=True, host='0.0.0.0', port=5000)