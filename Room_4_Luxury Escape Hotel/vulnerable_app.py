from flask import Flask, request, render_template_string, Response
import requests
import base64

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        resource_url = request.form.get('resource_url')
        if resource_url:
            try:
                response = requests.get(resource_url)
                content_type = response.headers.get('Content-Type')
                if content_type and 'image' in content_type:
                    data = base64.b64encode(response.content).decode('utf-8')
                    return render_template_string('''
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>Luxury Escape Hotel</title>
                            <style>
                                body {
                                    font-family: Arial, sans-serif;
                                    background-color: #f2f2f2;
                                    margin: 0;
                                    padding: 0;
                                }
                                .header {
                                    background-color: #333;
                                    color: #fff;
                                    padding: 20px;
                                    text-align: center;
                                }
                                .container {
                                    padding: 20px;
                                }
                                h1 {
                                    color: #333;
                                }
                                form {
                                    margin-top: 20px;
                                }
                                input[type="text"] {
                                    width: 300px;
                                    padding: 10px;
                                    border: 1px solid #ccc;
                                }
                                input[type="submit"] {
                                    padding: 10px 20px;
                                    background-color: #333;
                                    color: #fff;
                                    border: none;
                                    cursor: pointer;
                                }
                                img {
                                    margin-top: 20px;
                                    max-width: 100%;
                                    height: auto;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="header">
                                <h1>Welcome to Luxury Escape Hotel</h1>
                            </div>
                            <div class="container">
                                <h2>Explore Our Rooms</h2>
                                <form method="POST">
                                    Enter Resource URL: <input name="resource_url" type="text" />
                                    <input type="submit" value="View Resource" />
                                </form>
                                <img src="data:{{ content_type }};base64,{{ data }}" alt="Room Image"/>
                            </div>
                        </body>
                        </html>
                    ''', data=data, content_type=content_type)
                else:
                    data = response.text
                    return render_template_string('''
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>Luxury Escape Hotel</title>
                            <style>
                                body {
                                    font-family: Arial, sans-serif;
                                    background-color: #f2f2f2;
                                    margin: 0;
                                    padding: 0;
                                }
                                .header {
                                    background-color: #333;
                                    color: #fff;
                                    padding: 20px;
                                    text-align: center;
                                }
                                .container {
                                    padding: 20px;
                                }
                                h1 {
                                    color: #333;
                                }
                                form {
                                    margin-top: 20px;
                                }
                                input[type="text"] {
                                    width: 300px;
                                    padding: 10px;
                                    border: 1px solid #ccc;
                                }
                                input[type="submit"] {
                                    padding: 10px 20px;
                                    background-color: #333;
                                    color: #fff;
                                    border: none;
                                    cursor: pointer;
                                }
                                pre {
                                    background-color: #fff;
                                    padding: 10px;
                                    border: 1px solid #ccc;
                                    overflow: auto;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="header">
                                <h1>Welcome to Luxury Escape Hotel</h1>
                            </div>
                            <div class="container">
                                <h2>Resource Content</h2>
                                <form method="POST">
                                    Enter Resource URL: <input name="resource_url" type="text" />
                                    <input type="submit" value="View Resource" />
                                </form>
                                <pre>{{ data }}</pre>
                            </div>
                        </body>
                        </html>
                    ''', data=data)
            except Exception as e:
                return render_template_string('''
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Luxury Escape Hotel</title>
                        <style>
                            body {
                                font-family: Arial, sans-serif;
                                background-color: #f2f2f2;
                                margin: 0;
                                padding: 0;
                            }
                            .header {
                                background-color: #333;
                                color: #fff;
                                padding: 20px;
                                text-align: center;
                            }
                            .container {
                                padding: 20px;
                            }
                            h1 {
                                color: #333;
                            }
                            form {
                                margin-top: 20px;
                            }
                            input[type="text"] {
                                width: 300px;
                                padding: 10px;
                                border: 1px solid #ccc;
                            }
                            input[type="submit"] {
                                padding: 10px 20px;
                                background-color: #333;
                                color: #fff;
                                border: none;
                                cursor: pointer;
                            }
                            p {
                                color: red;
                            }
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h1>Welcome to Luxury Escape Hotel</h1>
                        </div>
                        <div class="container">
                            <h2>Error Loading Resource</h2>
                            <p>{{ error_message }}</p>
                            <form method="POST">
                                Enter Resource URL: <input name="resource_url" type="text" />
                                <input type="submit" value="View Resource" />
                            </form>
                        </div>
                    </body>
                    </html>
                ''', error_message=str(e))
        else:
            return render_template_string('''
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Luxury Escape Hotel</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            background-color: #f2f2f2;
                            margin: 0;
                            padding: 0;
                        }
                        .header {
                            background-color: #333;
                            color: #fff;
                            padding: 20px;
                            text-align: center;
                        }
                        .container {
                            padding: 20px;
                        }
                        h1 {
                            color: #333;
                        }
                        form {
                            margin-top: 20px;
                        }
                        input[type="text"] {
                            width: 300px;
                            padding: 10px;
                            border: 1px solid #ccc;
                        }
                        input[type="submit"] {
                            padding: 10px 20px;
                            background-color: #333;
                            color: #fff;
                            border: none;
                            cursor: pointer;
                        }
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>Welcome to Luxury Escape Hotel</h1>
                    </div>
                    <div class="container">
                        <h2>Explore Our Rooms</h2>
                        <form method="POST">
                            Enter Resource URL: <input name="resource_url" type="text" />
                            <input type="submit" value="View Resource" />
                        </form>
                    </div>
                </body>
                </html>
            ''')
    else:
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Luxury Escape Hotel</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f2f2f2;
                        margin: 0;
                        padding: 0;
                    }
                    .header {
                        background-color: #333;
                        color: #fff;
                        padding: 20px;
                        text-align: center;
                    }
                    .container {
                        padding: 20px;
                    }
                    h1 {
                        color: #333;
                    }
                    form {
                        margin-top: 20px;
                    }
                    input[type="text"] {
                        width: 300px;
                        padding: 10px;
                        border: 1px solid #ccc;
                    }
                    input[type="submit"] {
                        padding: 10px 20px;
                        background-color: #333;
                        color: #fff;
                        border: none;
                        cursor: pointer;
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>Welcome to Luxury Escape Hotel</h1>
                </div>
                <div class="container">
                    <h2>Explore Our Rooms</h2>
                    <form method="POST">
                        Enter Resource URL: <input name="resource_url" type="text" />
                        <input type="submit" value="View Resource" />
                    </form>
                </div>
            </body>
            </html>
        ''')

@app.route('/admin')
def admin():
    if request.remote_addr != '127.0.0.1':
        return "Access Denied."
    else:
        return "Congratulations! You have successfully exploited the SSRF vulnerability!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)