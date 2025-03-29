from flask import Flask, render_template_string

app = Flask(__name__)

# Main page
@app.route('/')
def home():
    return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <title>StrongBody Fitness Center</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fafafa; color: #333; }
        header { background-color: #333; color: #fff; padding: 20px; text-align: center; }
        nav { margin: 0; padding: 10px; background-color: #eee; text-align: center; }
        nav a { margin: 15px; color: #333; text-decoration: none; font-weight: bold; }
        main { padding: 20px; text-align: center; }
        footer { background-color: #333; color: #fff; padding: 10px; text-align: center; position: fixed; width: 100%; bottom: 0; }
    </style>
</head>
<body>
    <header>
        <h1>Welcome to StrongBody Fitness Center</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/classes">Classes</a>
        <a href="/trainers">Our Trainers</a>
        <a href="/contact">Contact Us</a>
    </nav>
    <main>
        <h2>Your health is our priority.</h2>
        <p>Join us for fitness classes, personal training, and more!</p>
        <img src="https://via.placeholder.com/800x300" alt="Fitness Center" style="width:80%; height:auto; margin-top:20px;">
    </main>
    <!-- TODO: Remove before deployment -->
    <!-- Admin login page at /admin_login -->
    <footer>
        &copy; 2023 StrongBody Fitness Center
    </footer>
</body>
</html>
''')

# Classes page
@app.route('/classes')
def classes():
    return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <title>Our Classes - StrongBody Fitness Center</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fafafa; color: #333; padding: 20px; }
        h1 { text-align: center; }
        ul { list-style-type: none; }
        li { margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Our Classes</h1>
    <ul>
        <li>Yoga</li>
        <li>Pilates</li>
        <li>Spinning</li>
        <li>Cardio Blast</li>
        <li>Strength Training</li>
    </ul>
</body>
</html>
''')

# Trainers page
@app.route('/trainers')
def trainers():
    return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <title>Our Trainers - StrongBody Fitness Center</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fafafa; color: #333; padding: 20px; }
        h1 { text-align: center; }
        .trainer { margin: 20px 0; }
        .trainer img { float: left; margin-right: 20px; border-radius: 50%; }
        .trainer:after { content: ""; display: table; clear: both; }
    </style>
</head>
<body>
    <h1>Meet Our Trainers</h1>
    <div class="trainer">
        <img src="https://via.placeholder.com/100" alt="Trainer Photo">
        <h2>Alex Smith</h2>
        <p>Certified Personal Trainer with 10 years of experience.</p>
    </div>
    <div class="trainer">
        <img src="https://via.placeholder.com/100" alt="Trainer Photo">
        <h2>Jamie Lee</h2>
        <p>Yoga and Pilates instructor specializing in flexibility.</p>
    </div>
</body>
</html>
''')

# Contact page
@app.route('/contact')
def contact():
    return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <title>Contact Us - StrongBody Fitness Center</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #fafafa; color: #333; padding: 20px; text-align: center; }
        form { display: inline-block; text-align: left; margin-top: 20px; }
        label { display: block; margin: 10px 0 5px; }
        input, textarea { width: 300px; padding: 8px; }
        button { margin-top: 10px; padding: 10px 20px; }
    </style>
</head>
<body>
    <h1>Contact Us</h1>
    <p>Email: info@strongbodyfitness.com</p>
    <form>
        <label for="name">Name:</label>
        <input type="text" id="name" name="name" placeholder="Your Name">
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" placeholder="Your Email">
        <label for="message">Message:</label>
        <textarea id="message" name="message" rows="5" placeholder="Your Message"></textarea>
        <button type="submit">Send Message</button>
    </form>
</body>
</html>
''')

# Hidden admin login page, should be protected
@app.route('/admin_login')
def admin_login():
    # Misconfiguration: Page accessible without proper authentication
    return render_template_string('''<!DOCTYPE html>
<html>
<head>
    <title>Admin Login - StrongBody Fitness Center</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #222; color: #0f0; text-align: center; padding-top: 100px; }
        h1 { font-size: 50px; }
        p { font-size: 24px; }
    </style>
</head>
<body>
    <h1>Congratulations!</h1>
    <p>You have accessed the Admin Login page.</p>
    <p>Great job finding and exploiting the security misconfiguration.</p>
</body>
</html>
''')

if __name__ == '__main__':
    app.run()