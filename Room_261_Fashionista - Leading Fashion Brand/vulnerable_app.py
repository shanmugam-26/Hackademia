from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    feedback = ""
    if request.method == "POST":
        comment = request.form.get("comment", "")
        feedback = comment  # XSS vulnerability here
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Fashionista - Leading Fashion Brand</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .brand {
            font-family: 'Arial', sans-serif;
            text-align: center;
            margin-top: 50px;
        }
        .brand h1 {
            font-size: 4em;
            color: #343a40;
        }
        .brand p {
            font-size: 1.5em;
            color: #6c757d;
        }
        .comment-box {
            margin-top: 30px;
        }
        .comments {
            margin-top: 20px;
        }
        #congrats {
            display: none;
            text-align: center;
            margin-top: 20px;
            color: green;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="brand">
            <h1>Fashionista</h1>
            <p>Discover Your Style</p>
        </div>
        <div class="comment-box">
            <form method="post">
                <div class="form-group">
                    <label for="comment">Leave a comment:</label>
                    <input type="text" class="form-control" name="comment" id="comment" placeholder="What do you think about our new collection?">
                </div>
                <button type="submit" class="btn btn-dark">Submit</button>
            </form>
        </div>
        <div class="comments">
            <h3>Recent Comments:</h3>
            <p>{{ feedback }}</p>
        </div>
        <div id="congrats">
            <h2>Congratulations! You've successfully exploited the XSS vulnerability.</h2>
        </div>
    </div>
</body>
</html>
''', feedback=feedback)

if __name__ == "__main__":
    app.run(debug=True)