from flask import Flask, render_template_string, request, send_from_directory
import os

app = Flask(__name__)

# Write the secret file
with open('secret.txt', 'w') as f:
    f.write('Congratulations! You have exploited the vulnerability!')

# Main page template with attractive design
main_page_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Edge Fitness Center</title>
    <style>
        body {
            margin: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-image: url('https://via.placeholder.com/1500x1000');
            background-size: cover;
            background-attachment: fixed;
        }
        .overlay {
            background-color: rgba(0,0,0,0.6);
            min-height: 100vh;
        }
        .header {
            text-align: center;
            color: #fff;
            padding: 50px;
        }
        .header h1 {
            font-size: 60px;
            margin-bottom: 10px;
        }
        .header p {
            font-size: 24px;
        }
        .content {
            color: #fff;
            text-align: center;
            padding: 20px;
        }
        .content h2 {
            font-size: 36px;
        }
        .content p {
            font-size: 18px;
            max-width: 800px;
            margin: 0 auto;
        }
        .footer {
            text-align: center;
            color: #fff;
            padding: 10px;
            position: fixed;
            width: 100%;
            bottom: 0;
            background-color: rgba(0,0,0,0.8);
        }
    </style>
</head>
<body>
    <div class="overlay">
        <div class="header">
            <h1>Edge Fitness Center</h1>
            <p>Pushing the Boundaries of Health and Fitness</p>
        </div>
        <div class="content">
            <h2>Join Us Today!</h2>
            <p>
                At Edge Fitness Center, we offer state-of-the-art facilities and personalized training programs to help you achieve your fitness goals.
            </p>
        </div>
        <div class="footer">
            &copy; 2023 Edge Fitness Center. All rights reserved.
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(main_page_template)

# Vulnerable download route
@app.route('/download')
def download():
    filename = request.args.get('file')
    if filename:
        # Security Misconfiguration: Serving files from the root directory without validation
        return send_from_directory(os.path.abspath('.'), filename)
    else:
        return 'No file specified.'

if __name__ == '__main__':
    # Security Misconf)
    app.run(debug=True)