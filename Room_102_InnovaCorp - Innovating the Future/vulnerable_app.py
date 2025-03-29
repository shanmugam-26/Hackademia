from flask import Flask, render_template_string, request, Response
import base64

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    page = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>InnovaCorp - Innovating the Future</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
            section { padding: 20px; }
            footer { background-color: #333; color: white; text-align: center; padding: 10px; position: relative; bottom: 0; width: 100%; }
            .login-form { max-width: 300px; margin: auto; }
            input[type=text], input[type=password] { width: 100%; padding: 12px 20px; margin: 8px 0; box-sizing: border-box; }
            input[type=submit] { background-color: #4CAF50; color: white; padding: 14px 20px; margin: 8px 0; border: none; cursor: pointer; width: 100%; }
            input[type=submit]:hover { background-color: #45a049; }
        </style>
    </head>
    <body>
        <header>
            <h1>InnovaCorp</h1>
            <p>Innovating the Future of Technology</p>
        </header>
        <section>
            <h2>Welcome to InnovaCorp</h2>
            <p>At InnovaCorp, we are developing cutting-edge technology solutions that will revolutionize the way you interact with the world.</p>
            <div class="login-form">
                <h3>Login to your account</h3>
                <form action="/" method="post">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" placeholder="Enter Username">

                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="Enter Password">

                    <input type="submit" value="Login">
                </form>
            </div>
        </section>
        <footer>
            <p>&copy; 2023 InnovaCorp. All rights reserved.</p>
        </footer>
        <script>
            // The following JavaScript code makes a request to get user data
            // Obfuscated for complexity
            (function(){
                function decode(str) {
                    return decodeURIComponent(atob(str).split('').map(function(c) {
                        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
                    }).join(''));
                }
                var secret = 'JTVCJTIydG9rZW4lMjIlM0ElMjIlMkJzZXNyZXQxMjMlMkIlMjIlNUQ=';
                var xhr = new XMLHttpRequest();
                xhr.open('GET', '/api/secret_data?token=' + decode(secret), true);
                xhr.onreadystatechange = function() {
                    if (xhr.readyState == 4 && xhr.status == 200) {
                        console.log('Secret Data:', xhr.responseText);
                    }
                };
                xhr.send();
            })();
        </script>
    </body>
    </html>
    '''
    if request.method == 'POST':
        # Simulate processing login (details omitted for security)
        pass
    return render_template_string(page)

@app.route('/api/secret_data')
def secret_data():
    token = request.args.get('token')
    if token == '==s3cret123==':
        return 'Confidential Company Data'
    else:
        return 'Invalid token', 403

@app.route('/congrats')
def congrats():
    return 'Congratulations! You have successfully exploited the Insecure Communication vulnerability.'

if __name__ == '__main__':
    app.run()