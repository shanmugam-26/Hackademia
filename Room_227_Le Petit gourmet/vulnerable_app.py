from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

# Simulated database of reservations
reservations = []

@app.route('/')
def home():
    return render_template_string(index_html)

@app.route('/reserve', methods=['POST'])
def reserve():
    name = request.form.get('name')
    date = request.form.get('date')
    time = request.form.get('time')
    guests = request.form.get('guests')
    reservations.append({
        'name': name,
        'date': date,
        'time': time,
        'guests': guests
    })
    return redirect(url_for('home'))

@app.route('/admin')
def admin():
    # Improper Access Control: This admin page should require authentication but doesn't
    return render_template_string(admin_html, reservations=reservations)

@app.route('/congratulations')
def congratulations():
    return render_template_string(congrats_html)

# HTML Templates
index_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Le Petit gourmet</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-image: url('https://images.unsplash.com/photo-1528605248644-14dd04022da1');
               background-size: cover; color: #fff; }
        .container { background: rgba(0,0,0,0.7); padding: 20px; margin-top: 50px; border-radius: 10px; }
        h1, h2 { font-family: 'Georgia', serif; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Le Petit Gourmet</h1>
        <p>Experience fine dining like never before. Indulge in exquisite dishes crafted by world-renowned chefs.</p>
        <h2>Make a Reservation</h2>
        <form action="/reserve" method="post">
            <div class="form-group">
                <label for="name">Name</label>
                <input type="text" id="name" name="name" class="form-control" required/>
            </div>
            <div class="form-group">
                <label for="date">Date of Reservation</label>
                <input type="date" id="date" name="date" class="form-control" required/>
            </div>
            <div class="form-group">
                <label for="time">Time of Reservation</label>
                <input type="time" id="time" name="time" class="form-control" required/>
            </div>
            <div class="form-group">
                <label for="guests">Number of Guests</label>
                <input type="number" id="guests" name="guests" class="form-control" required/>
            </div>
            <button type="submit" class="btn btn-primary">Reserve Now</button>
        </form>
    </div>
</body>
</html>
'''

admin_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Panel - Le Petit Gourmet</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #f8f9fa; }
        .container { margin-top: 50px; }
        h1 { margin-bottom: 30px; }
        table { background-color: #fff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Panel</h1>
        <h2>Current Reservations</h2>
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Date</th>
                    <th>Time</th>
                    <th>Guests</th>
                </tr>
            </thead>
            <tbody>
                {% for reservation in reservations %}
                <tr>
                    <td>{{ reservation.name }}</td>
                    <td>{{ reservation.date }}</td>
                    <td>{{ reservation.time }}</td>
                    <td>{{ reservation.guests }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
'''

congrats_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Congratulations!</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body { background-color: #28a745; color: #fff; }
        .container { margin-top: 100px; text-align: center; }
        h1 { font-size: 4em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Congratulations!</h1>
        <p>You have successfully exploited the Improper Access Control vulnerability.</p>
    </div>
</body>
</html>
'''
if __name__ == '__main__':
        app.run(debug=True)