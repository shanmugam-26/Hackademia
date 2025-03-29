from flask import Flask, request, render_template_string, make_response

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        # Process login (accept any credentials)
        response = make_response(render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Welcome {{username}} - InnovateTech Solutions</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
                    .container { width: 50%; margin: auto; background-color: #fff; padding: 20px; }
                    h1 { color: #333; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Welcome, {{username}}!</h1>
                    <p>Thank you for logging in to the InnovateTech internal system.</p>
                    <p>As a valued member of our team, you have access to exclusive company resources.</p>
                    <!-- Hidden message -->
                    <!-- The flag is: FLAG{Insecure_Communication_Detected} -->
                </div>
            </body>
            </html>
        ''', username=username))
        # Include a custom header with a flag
        response.headers['X-Flag'] = 'Congratulations! You have found the flag: FLAG{Insecure_Communication_Detected}'
        return response
    else:
        # Display the login page
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>InnovateTech Solutions - Login</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f4f4f4; }
                    .container { width: 30%; margin: auto; background-color: #fff; padding: 50px; margin-top: 100px; box-shadow: 0 0 10px rgba(0,0,0,0.1);}
                    h1 { color: #333; text-align: center;}
                    input[type="text"], input[type="password"] {
                        width: 100%;
                        padding: 12px 20px;
                        margin: 8px 0;
                        display: inline-block;
                        border: 1px solid #ccc;
                        box-sizing: border-box;
                    }
                    button {
                        background-color: #4285F4;
                        color: white;
                        padding: 14px 20px;
                        margin: 8px 0;
                        border: none;
                        cursor: pointer;
                        width: 100%;
                    }
                    button:hover {
                        opacity: 0.8;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>InnovateTech Solutions</h1>
                    <form method="POST" action="/">
                        <label for="username">Username:</label><br>
                        <input type="text" id="username" name="username" required><br>
                        <label for="password">Password:</label><br>
                        <input type="password" id="password" name="password" required><br><br>
                        <button type="submit">Login</button>
                    </form>
                </div>
            </body>
            </html>
        ''')

if __name__ == '__main__':
    app.run()