from flask import Flask, render_template_string, request, redirect, url_for

app = Flask(__name__)

# Main page HTML
main_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Anderson & Co. Law Firm</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background-color: #f4f4f4; }
        header { background-color: #2c3e50; color: #fff; padding: 20px; text-align: center; }
        nav { background-color: #34495e; overflow: hidden; }
        nav a { float: left; display: block; color: #fff; text-align: center; padding: 14px 16px; text-decoration: none; }
        nav a:hover { background-color: #ddd; color: black; }
        .banner { background-image: url('https://via.placeholder.com/1200x400'); background-size: cover; height: 400px; }
        .content { padding: 20px; }
        footer { background-color: #2c3e50; color: #fff; padding: 10px; text-align: center; position: fixed; bottom: 0; width: 100%; }
    </style>
</head>
<body>
    <header>
        <h1>Anderson & Co. Law Firm</h1>
        <p>Professional Legal Services Since 1990</p>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="/about">About Us</a>
        <a href="/services">Our Services</a>
        <a href="/contact">Contact</a>
        <a href="/login">Client Login</a>
    </nav>
    <div class="banner"></div>
    <div class="content">
        <h2>Welcome to Anderson & Co.</h2>
        <p>At Anderson & Co., we are committed to providing exceptional legal services to our clients. Our team of experienced attorneys specializes in various areas of law to meet all your legal needs.</p>
    </div>
    <footer>
        &copy; 2023 Anderson & Co. Law Firm
    </footer>
</body>
</html>
'''

# Login page HTML
login_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Client Login - Anderson & Co. Law Firm</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
        .login-container { width: 300px; margin: 100px auto; padding: 20px; background-color: #ecf0f1; border-radius: 5px; }
        input[type=text], input[type=password] { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #bdc3c7; border-radius: 4px; }
        button { width: 100%; background-color: #2c3e50; color: white; padding: 14px 20px; margin: 8px 0; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #34495e; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Client Login</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required /><br/>
            <input type="password" name="password" placeholder="Password" required /><br/>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
'''

# Contact page HTML
contact_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Contact Us - Anderson & Co. Law Firm</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
        .contact-container { width: 600px; margin: 50px auto; padding: 20px; background-color: #ecf0f1; border-radius: 5px; }
        h2 { text-align: center; }
        p { line-height: 1.6; }
    </style>
</head>
<body>
    <div class="contact-container">
        <h2>Contact Us</h2>
        <p><strong>Address:</strong> 456 Justice Drive, Suite 800, Metropolis, USA</p>
        <p><strong>Phone:</strong> (555) 987-6543</p>
        <p><strong>Email:</strong> contact@andersonlaw.com</p>
        <p>Our office hours are Monday to Friday, 9 AM to 6 PM. We look forward to assisting you with your legal matters.</p>
    </div>
</body>
</html>
'''

# Admin dashboard HTML (Improperly protected)
admin_page_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Admin Dashboard - Anderson & Co. Law Firm</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
        .admin-container { width: 800px; margin: 50px auto; padding: 20px; background-color: #ecf0f1; border-radius: 5px; }
        h2 { color: #e74c3c; }
        table { width: 100%; border-collapse: collapse; }
        table, th, td { border: 1px solid #bdc3c7; }
        th, td { padding: 12px; text-align: left; }
        th { background-color: #34495e; color: white; }
    </style>
</head>
<body>
    <div class="admin-container">
        <h2>Admin Dashboard</h2>
        <p>Welcome, Administrator!</p>
        <p>Below are the latest confidential client records:</p>
        <table>
            <tr>
                <th>Client ID</th>
                <th>Name</th>
                <th>Case Details</th>
                <th>Status</th>
            </tr>
            <tr>
                <td>1023</td>
                <td>John Doe</td>
                <td>Corporate Merger</td>
                <td>In Progress</td>
            </tr>
            <tr>
                <td>1045</td>
                <td>Jane Smith</td>
                <td>Intellectual Property Dispute</td>
                <td>Pending</td>
            </tr>
            <!-- More confidential data -->
        </table>
        <p><strong>Congratulations!</strong> You have successfully accessed the admin dashboard.</p>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(main_page_html)

@app.route('/about')
def about():
    about_page_html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>About Us - Anderson & Co. Law Firm</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
            .about-container { width: 800px; margin: 50px auto; padding: 20px; background-color: #ecf0f1; border-radius: 5px; }
            h2 { text-align: center; }
            p { line-height: 1.6; }
        </style>
    </head>
    <body>
        <div class="about-container">
            <h2>About Us</h2>
            <p>Since 1990, Anderson & Co. has been providing top-tier legal services to individuals and businesses nationwide. Our team is comprised of seasoned attorneys who are experts in their respective fields.</p>
            <p>We pride ourselves on our commitment to our clients, ensuring personalized attention and tailored legal strategies that meet your unique needs.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(about_page_html)

@app.route('/services')
def services():
    services_page_html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Our Services - Anderson & Co. Law Firm</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
            .services-container { width: 800px; margin: 50px auto; padding: 20px; background-color: #ecf0f1; border-radius: 5px; }
            h2 { text-align: center; }
            ul { list-style-type: square; }
            li { margin-bottom: 10px; }
        </style>
    </head>
    <body>
        <div class="services-container">
            <h2>Our Services</h2>
            <ul>
                <li>Corporate Law</li>
                <li>Intellectual Property</li>
                <li>Family Law</li>
                <li>Real Estate Law</li>
                <li>Litigation and Dispute Resolution</li>
            </ul>
            <p>Our firm offers a wide range of legal services designed to meet the diverse needs of our clients. Contact us to learn more about how we can assist you.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(services_page_html)

@app.route('/contact')
def contact():
    return render_template_string(contact_page_html)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # For demonstration purposes, the login functionality is not implemented
        username = request.form.get('username')
        password = request.form.get('password')
        # In a real application, you would verify the username and password
        return redirect(url_for('client_dashboard'))
    return render_template_string(login_page_html)

@app.route('/client-dashboard')
def client_dashboard():
    client_dashboard_html = '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Client Dashboard - Anderson & Co. Law Firm</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
            .client-container { width: 800px; margin: 50px auto; padding: 20px; background-color: #ecf0f1; border-radius: 5px; }
            h2 { color: #27ae60; }
            p { line-height: 1.6; }
        </style>
    </head>
    <body>
        <div class="client-container">
            <h2>Client Dashboard</h2>
            <p>Welcome to your client dashboard. Here you can access your case files, communicate with your attorney, and stay updated on the progress of your legal matters.</p>
        </div>
    </body>
    </html>
    '''
    return render_template_string(client_dashboard_html)

@app.route('/admin')
def admin_dashboard():
    # Improper Access Control: This admin page should be protected by authentication but is not
    # TODO: Implement authentication check to secure this route
    return render_template_string(admin_page_html)

if __name__ == '__main__':
    app.run(debug=True)